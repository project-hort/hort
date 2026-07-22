# 039 — Mirror push 429: auth-scope limiter counts failures only (+ serialize mirror jobs)

**Issue:** #66
**Read first:** `crates/hort-http-core/src/middleware/rate_limit.rs` (esp. module doc lines
25-56, `rate_limit_middleware_impl` ~286, `auth_rate_limit_layer` ~391),
`crates/hort-http-core/src/router.rs` (105-143 attach + rationale, `method_based_auth_dispatch`
~276), `crates/hort-http-core/src/middleware/auth.rs` (`require_principal` ~199),
`docs/auth-catalog.md` (rate-limit posture), `.github/workflows/docker-publish.yml`
(`mirror-to-hort-oci` / `mirror-to-hort-base`). This is architecture-affecting security
middleware — **use `/hort-architect`** and read the auth posture before coding.

## Problem (confirmed in code + Tom's host logs)

`cosign copy` bulk multi-arch pushes to the hosted `hort-oci` / `hort-base` repos 429 under
concurrent load. Root cause: the **auth-scope** limiter (`HORT_RATELIMIT_AUTH_PER_MIN`,
default **60/min** per IP) is a **global pre-validation layer** attached over
`method_based_auth_dispatch` (router.rs:105-143). Every write draws down **both** the auth (60)
and write (300) buckets, so the effective ceiling is `min(auth, write) = 60/min` — and a
multi-arch push is far more than 60 authenticated blob/manifest writes/min from one runner IP.
Tom's host logs confirm: all 9 rejections were `scope:auth`, with correct per-IP resolution
(not an XFF collapse). The 500 INTERNAL is a **knock-on** of the 429'd incomplete blob uploads
(no server error logged; manifests ingested) — fixing the 429 resolves it; it is **not** in
scope here.

## Fix — the auth-scope limiter counts authentication *failures* only

An authenticated request carrying a **valid principal** is not a credential-stuffing attempt and
must not draw down the anti-credential-stuffing bucket. Change the auth-scope limiter so it
consumes/rejects on **auth failure** (or anonymous credential-presentation), not on every write.
Authenticated writes then fall under the **write** scope (300/min) alone — the control actually
meant for authenticated throughput.

### Hard invariants (the security contract — all must hold, with tests)

1. **Pre-validation throttle preserved.** A flood of failing/anonymous auth attempts from one IP
   is still rejected at `auth_per_min` **before** `require_principal` runs JWKS/IdP validation
   (router.rs:111-114 is load-bearing — do NOT regress it). The attacker must not be able to
   burn the validation path past the cap.
2. **`POST /api/v1/auth/exchange` stays throttled.** It's anonymous (bypasses `require_principal`)
   but is the primary credential→token surface (ADR 0013); credential-stuffing there must still
   trip `auth_per_min`.
3. **Valid-principal writes do NOT consume the auth bucket.** An authenticated client pushing
   >`auth_per_min` writes/min from one IP is limited only by the write scope (300/min), never
   429'd by auth-scope.
4. **Write scope unchanged.** `HORT_RATELIMIT_WRITE_PER_MIN` (300) still bounds authenticated
   throughput, including a compromised-token abuse flood (the doc's stated write-scope threat).

### Suggested mechanic (implementer's call; invariants + tests are the contract)

Governor's keyed limiter couples check+consume with **no peek and no refund**, so the naive
"consume on entry, refund on success" is infeasible. Two viable shapes:
- **Preferred:** a small per-IP **failure-window counter** for the auth scope — checked+rejected
  on entry (before validation), incremented only when the downstream response is an auth failure
  (401/403) or an anonymous credential-reject. Keeps invariant 1 (entry check) + invariant 3
  (no tick on success). ~self-contained, sidesteps governor's limitations for this scope.
- Alternatively keep governor but consume only on the failure path with a separate entry gate.

Do **not** narrow the attach point to drop auth-scope off `/v2/**` entirely — that would violate
invariant 1 (bad-bearer floods on `/v2/**` would lose pre-validation throttling).

### Docs (required, same change)
- Rewrite the `rate_limit.rs` module-doc "Scope overlap" section (lines 25-56) — it currently
  documents the `min(auth,write)` coupling as *intentional*; that rationale is being corrected.
- Update `docs/auth-catalog.md` rate-limit posture to match.
- Flag in the MR whether this warrants an ADR (it refines an existing documented control rather
  than making a new decision — a doc update likely suffices, but call it out for review).

## Part B — serialize the two mirror jobs (defense-in-depth, workflow only)

In `.github/workflows/docker-publish.yml`, make `mirror-to-hort-base` `needs: [mirror-to-hort-oci]`
so the two bulk pushes don't hammer registry.hort.rs concurrently, and cap `cosign copy`
concurrency if the tool exposes it. This halves peak write rate; it is **not** sufficient alone
(the auth-scope fix is the real fix) but is cheap insurance.

## Acceptance

- New tests prove invariants 1-4 (bad-token flood → 429 pre-validation; `/auth/exchange` flood
  → 429; valid-token bulk writes > `auth_per_min` → not auth-429'd, only write-capped; write
  scope unchanged).
- `rate_limit.rs` module doc + `docs/auth-catalog.md` updated to the new posture.
- `mirror-to-hort-base` serialized after `mirror-to-hort-oci`.
- Full gate green: `cargo test --workspace`, `fmt`, `clippy`, `audit`, `deny`.

### Starter prompt

```
/hort-architect

Implement backlog item 039 (issue #66) on branch agent/66-mirror-push-ratelimit.
Security middleware — read rate_limit.rs (module doc 25-56, rate_limit_middleware_impl,
auth_rate_limit_layer), router.rs (105-143 + method_based_auth_dispatch), auth.rs
(require_principal), and docs/auth-catalog.md FIRST. Make the auth-scope rate limiter count
authentication FAILURES only, so authenticated (valid-principal) writes fall under the write
scope (300/min) instead of the auth scope (60/min). Honor all four hard invariants in the
backlog item — especially #1: failed/anonymous auth floods must still be rejected at auth_per_min
BEFORE require_principal runs JWKS validation (router.rs:111-114). Add tests for all four
invariants. Update the rate_limit.rs module-doc "Scope overlap" section and docs/auth-catalog.md.
Then serialize mirror-to-hort-base after mirror-to-hort-oci in docker-publish.yml. Run the full
gate and report per the handover protocol; flag whether an ADR is warranted.
```
