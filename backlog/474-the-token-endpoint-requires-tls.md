# 474 — the token endpoint requires TLS

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 4 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §1 (what binds us), §3, §4.4.
**Depends on 471 and 472.** The §3 decision is answered; §3.2 settles this
unit's own question, which was the decision's sharpest case.
**Read first:** `crates/hort-http-core/src/handlers/exchange.rs` (module
header's order-of-validation list, `post_exchange`, `handle_federated_jwt`),
`crates/hort-http-core/src/router.rs:258-270`, `docs/auth-catalog.md` Entry 6.

## The defect, and why this one is not a judgement call

`POST /api/v1/auth/exchange` is short-circuited out of the shared auth
dispatch by design (`router.rs:258-270`), takes the credential in an
`application/x-www-form-urlencoded` body that `resolve_token` never inspects,
and **mints and returns a token** — a signed CliSession JWT, or a
`ServiceAccount` token on the federated branch (`exchange.rs:463-473`).
Neither the inbound credential nor the issued one has any transport rule.

RFC 6749 §3.2: *"Since requests to the token endpoint result in the
transmission of clear-text credentials (in the HTTP request and response), the
authorization server MUST require the use of TLS as described in Section 1.6
when sending requests to the token endpoint."* That binds the authorization
server — this binary — and an RFC 8693 exchange is a token-endpoint request.
The specification outranks the implementation, so unlike the consume surfaces
this one is not satisfied by reasoning about exposure.

Unlike the bearer paths, the refusal here protects a secret that **does not
exist yet**.

## What to build

- Call `credential_transport_verdict` as the **first step after form
  parsing**, before the `grant_type` and token-type checks, before the
  PAT-shape gate, before the IdP call, before `handle_federated_jwt`, and
  before any mint. Add it to the module header's order-of-validation list.
- Refuse `426` in the endpoint's **own** envelope, plus
  `Upgrade: TLS/1.2, HTTP/1.1` and the `Cache-Control: no-store` the handler
  already sets. No `WWW-Authenticate` (the module header's rule).
- **One explicit reason string, in the `error_description` and in the refusal
  warning**, naming the asymmetry so an operator does not have to read the
  source to find it: TLS evidence is required for token exchange,
  `HORT_BEARER_ALLOW_OVER_HTTP` does not apply here, and the remedies are TLS
  or `HORT_TLS_NOT_REQUIRED_FROM` for this peer. This is the whole runtime fix
  for the one surface that behaves differently from the other five; without it
  the only signal is a `426` that contradicts an enabled flag and a boot
  warning that says bearer-over-HTTP is allowed
  (`crates/hort-server/src/composition.rs:300-306`).
- **Both** mint branches are covered by the one call — do not place it inside
  the access-token path only.
- `hort_credential_transport_refusals_total{entry_point="exchange"}`, in
  `docs/metrics-catalog.md` in this change.
- **Catalog Entry 6** in this same change (ADR 0018): name the enforcement
  **and** state that plaintext is accepted under a named operator waiver, so
  the Protection line does not keep reading as "TLS was observed" for a waived
  mint.
- **This endpoint honours evidence or a declared waiver, and NOT the unscoped
  `HORT_BEARER_ALLOW_OVER_HTTP`** (design §3.2). Write the reason at the site in
  the invariant form: the flag is unscoped and a transport setting must not
  silently extend to minting credentials on an unknown wire; a deployment that
  genuinely wants plaintext token exchange declares the scope it is talking to.
  No second development switch is introduced. The ADR (unit 477) records that
  RFC 6749 §3.2 conformance is **not claimed** for a request inside a waived
  scope — that sentence is the ADR's job, not this handler's.
- **Correct the stale module header** while here: the success example shows a
  `hort_cli_…` string (`exchange.rs:22-30`); the interactive branch returns a
  signed JWT.

## Acceptance

- An exchange over an unproven transport is refused `426` with the OAuth
  envelope, the `Upgrade` header and `no-store`, and **no IdP call, no
  federated validation and no mint happen** — assert all three, not the status
  alone.
- Both branches refuse: the access-token path and the federated-JWT path.
- The same request over `transport == Tls` succeeds exactly as today, on both
  branches.
- `HORT_BEARER_ALLOW_OVER_HTTP=true` does **not** make a plaintext exchange
  succeed — assert the refusal with the flag set, which is the one behaviour
  that distinguishes this surface from the other five.
- A peer inside `HORT_TLS_NOT_REQUIRED_FROM` succeeds, with `transport` still
  reading `Unknown`, on both mint branches.
- The module header's order-of-validation list names the new first step, and
  its success example no longer shows a `hort_cli_…` string.
- Gate: `cargo test --workspace`, clippy, fmt last. No uncovered new lines.
