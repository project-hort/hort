# 233 — A denial does not record which leg denied it

**Issue:** #239 · **Branch:** `agent/239-authz-denial-reason`
**Governing decisions:** ADR 0036 (the cap-intersection invariant — the two-leg
AND is load-bearing and is **not** touched here; only the reporting of its
result changes) · ADR 0012 (claim-based RBAC) · ADR 0017 (a metric series is
catalogued or it does not exist) · the module contract at the top of
`crates/hort-app/src/rbac.rs`.

## Why

`RbacEvaluator::authorize` computes `user_leg && cap_leg` and returns a bare
`bool`. Two structurally different failures are then indistinguishable at every
layer, and the caller sees the same `404` by anti-enumeration collapse:

- **No grant** — the identity genuinely has no permission on that repository.
- **Cap reject** — the identity *has* the permission, but the presented token
  carries a cap that excludes the repository.

This produced the same wrong diagnosis twice in one day, by two people working
carefully. On #237 the configuration was applied correctly and verified as
correct, and remained entirely ineffective: the token row carried
`repository_ids = {maven-proxy}` while the mint recipe passed no
`--repository`. Recipe and row had contradicted each other since August.
Nothing surfaced it, because a cap reject and a missing grant look identical.

The configuration can be completely correct in Git, the ticket can look
finished, and the path can still be unreachable with the same `404`.

**The distinction is already computed and thrown away.** Both legs are
evaluated unconditionally — deliberately, with a comment forbidding refactoring
the AND away. There is no hot-path cost to preserving the value.

## The module contract decides the design

`crates/hort-app/src/rbac.rs`, module docstring:

> Pure in-memory authorization predicate. No I/O, no async, no tracing.
> Deny-logging and metrics emission happen at the handler layer — **this module
> is a decision function, not an observer.**

So the evaluator does not emit. It **returns** the distinction, and the handler
layer — which already owns deny-logging and the decision counter — does what it
already does with everything else.

## Read first

- `crates/hort-app/src/rbac.rs` — `authorize` (the two legs),
  `user_grants_authorize`, `cap_allows_optional_repo`, `authorize_granted`
  (the grants leg alone — **unchanged**, its denial reason is never in
  question), and the module docstring above.
- `crates/hort-http-core/src/authz/extractors.rs` — `deny_hint`, and the two
  sites that call it (see below).
- `crates/hort-http-core/src/authz/mod.rs` — `emit_authz_decision`.
- `docs/metrics-catalog.md` — where the new series has to land.

## As-built, verified on develop — read this before planning the diff

- **`.authorize(` appears at 114 sites** across the workspace (tests included).
  The issue says "roughly thirty"; neither number is the one to plan against —
  **count the production sites yourself**. Whatever the count, it is the reason
  for the sibling-function shape: the diagnosability fix must not become a
  hundred-file diff reviewers have to read for behaviour changes that are not
  in it.
- **There are exactly two non-test callers of `deny_hint`**, and they are not
  the same shape:
  - `authorize_permission` (~line 777) — the general path. One
    `rbac.authorize(...)`, one counter, one hint. This is a clean swap.
  - `CurateOrAdminPrincipal::from_request_parts` (~line 310) — the **composite**:
    it tries `Permission::Curate`, then falls back to `Permission::Admin`, and
    emits one decision for the pair. See the wrinkle below.

## Scope

### 1. A returned decision, not an emitted one

In `rbac.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allowed,
    /// The grants leg failed; the cap would have allowed it.
    DeniedGrants,
    /// The grants leg passed; the presented token's cap excluded it.
    DeniedCap,
    /// Both legs failed.
    DeniedBoth,
}
```

`authorize_explained(…) -> AuthzDecision` holds the logic;
`authorize(…) -> bool` becomes `authorize_explained(…).is_allowed()` and keeps
its signature and meaning, so **no existing call site changes**.

`DeniedBoth` stays a distinct fourth state rather than folding into
`DeniedGrants`. Reporting one of two faults sends the operator round the loop
twice — the exact failure mode this item exists to end.

### 2. The hint stops guessing

`deny_hint` discriminates misconfiguration shapes from the *principal's shape*,
because that is all it has. Its own docstring records the blind spot:

> Claims present, `token_cap` set — the deny **could be either** the RBAC-grant
> miss above OR the token's cap narrowing the intersection. Operator needs to
> check both.

That case is replaced by the measured fact. Note the division of labour, and
keep it: **the decision says which leg failed; the principal shape still says
the likely remediation within that leg.** The empty-claims and
`CliSession`-without-admin branches remain useful and are not made redundant —
they explain *why the grants leg* failed. Only the "check both" arm and the
ServiceAccount arm's three-way checklist (a)/(b)/(c) become answerable.

**Two constraints.** `deny_hint` returns `&'static str` so the deny path
allocates nothing — preserve that; new arms are static strings too. And the
hint stays **advisory**, never load-bearing for the decision.

### 3. The composite site — decide it explicitly

`CurateOrAdminPrincipal` produces **two** decisions (curate, then admin) and one
deny. A single reason there would be a fiction: the two legs can fail
differently.

Recommended, but argue it: leave `deny_hint` as the principal-shape hint at that
site and add the two decisions as **separate tracing fields** — they are `Copy`
enums, `Debug`-formatted, so nothing is allocated and the `&'static str`
constraint on the hint is untouched. That reports more than a merged reason
could, without inventing one. If reaching the decisions there requires widening
`evaluate_rbac` / `authorize_silent`, say what you widened and why the narrower
option was worse.

### 4. A sibling counter, not a new label

Add `hort_authz_denials_total{permission, reason}` with
`reason ∈ {grants, cap, both}`, emitted **only** where a decision with a known
reason exists.

Leave `hort_authz_decisions_total{permission, result}` alone. It is emitted from
composite sites that have no single reason; a `reason` label there would force
an `unknown` value into a catalogued metric at exactly the sites where the
answer is most confusing — worse than not having the number.

Cardinality is bounded: permissions × three reasons, deny-only, **no
`repository` label** — the same cardinality-control decision the existing
counter documents.

`docs/metrics-catalog.md` gains the series. Uncatalogued means non-existent.

## Explicitly not in this item

**Whether the caller sees the difference.** A distinguishable client-visible
code for a cap reject is arguable — the caller holds the token and knows what
its cap covers — but it exposes that the identity's grants are broader than the
presented token's cap, which is a statement about the account's topology, and it
changes an externally observable contract that anti-enumeration currently
governs uniformly. That belongs to `docs/auth-catalog.md`, not beside a log
field. **The response stays `404`.**

Also out: any change to `authorize_granted`, to the AND itself, or to which
sites call which extractor.

## Acceptance

- `authorize_explained` returns each of the four variants under the conditions
  named, and `authorize`'s `bool` agrees with it for every input — pinned by a
  test that asserts the two cannot diverge.
- The diff outside `rbac.rs`, `extractors.rs`, the metrics catalog and tests is
  empty.
- A #237-shaped principal — grants global, token cap scoped to one *other*
  repository — yields `DeniedCap`, and the deny log names the cap instead of
  offering a checklist.
- No grant with an unscoped cap yields `DeniedGrants`; failing both yields
  `DeniedBoth`.
- `deny_hint` still returns `&'static str` and is still advisory.
- `hort_authz_denials_total` is catalogued and carries no `repository` label.
- The evaluator still contains no tracing and no metrics — the contract that
  decided this design is not eroded by the fix that cites it.
- 100 % coverage on the new `hort-app` branches; `hort-http-core` ≥ 85 %.
