# 473 — the OCI plane requires evidence

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 3 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §2.3, §4.3, §4.4.
**Depends on 471 and 472.** The §3 decision is answered (a declared hop is
acceptable, as a waiver), so this unit is unblocked.
**Read first:** `crates/hort-http-oci/src/middleware/oci_auth.rs:100-245`,
`crates/hort-http-oci/src/v2_auth.rs:125-212`,
`crates/hort-http-core/src/router.rs:245-262`, `docs/auth-catalog.md` Entry 7.

## The defect

`method_based_auth_dispatch` short-circuits the whole `/v2/*` subtree
(`router.rs:250-257`), so neither middleware in unit 472 ever sees an OCI
request. The subtree runs its own `oci_bearer_auth`, which accepts a Bearer
token or a Basic-carried JWT (`oci_auth.rs:143-245`) with **no transport check
of any kind** — and it deliberately skips `/v2/auth` (`oci_auth.rs:110-129`),
whose handler accepts a Basic PAT and **returns a freshly minted OCI JWT**
(`v2_auth.rs:175-212`).

So the OCI plane is two of the five credential surfaces, one of them an
issuing surface, and it carries nothing today — while catalog Entry 7 claims
"in transit — TLS" for exactly that token.

`/v2/auth` also has an **anonymous** mint path
(`v2_auth.rs:196-212`, `exchange_anonymous`) that returns a bearer for public
reads. Whether minting a public-read capability over plaintext is acceptable
is a policy this unit must **state**, not inherit: no credential is presented,
but one is issued.

## What to build

- Consume the **same** `credential_transport_verdict` from 472 — not a second
  copy in this crate. `Waived(scope)` behaves as `Allowed` for the wire and is
  counted apart, with the scope label taken from the verdict.
- `oci_bearer_auth`: refuse before the verify entrypoint, on the
  credential-present branch only. The existing anonymous pass-through for safe
  methods is unchanged; the anonymous **write** challenge is unchanged.
- `/v2/auth`: refuse before `OciTokenExchangeUseCase::exchange`, i.e. before
  the PAT is validated and before a token is minted.
- Refuse in the **OCI error shape** the subtree already uses, with the
  `WWW-Authenticate` posture its own helpers pick (never a `Bearer realm` the
  client cannot satisfy — the module header's existing rule). Mirror
  `unauthorized_response`'s mode awareness rather than inventing a shape.
- State the **anonymous-mint policy** at the site in the invariant form, and
  implement it. Default position, to be argued or overturned in the report: a
  mint is a credential-issuing response, so it requires evidence even when the
  request presented nothing — otherwise the one surface that creates a secret
  out of nothing is the one with no transport rule.
- `hort_credential_transport_refusals_total{entry_point}` for `oci_consume`
  and `oci_mint`, in `docs/metrics-catalog.md` in this change (ADR 0017).
- **Catalog Entry 7** in this same change (ADR 0018): name what enforces its
  TLS claim **and** state that plaintext is accepted under a named operator
  waiver — the claim must not keep reading as "TLS was observed" for a waived
  mint. Entry 7 already documents the anonymous token as a public-pull
  capability; it is still a bearer issuance, so it gets the same
  evidence-or-waiver rule with no anonymous exception.
- **Flip** both OCI surfaces in 472's structural guard census from
  observing-only to deciding, and replace each reason. Do **not** delete the
  lines: the census asserts that every `CredentialEntryPoint` variant is
  attributed to some production function, so a deleted line fails it. (Unit
  473's run corrected this wording, and the guard's own doc sentence, which
  said the same false thing.)

## Acceptance

- A Bearer or Basic credential on `/v2/*` over an unproven transport is
  refused in the OCI error shape; over `Tls` it is accepted exactly as today.
- A `/v2/auth` request with a Basic PAT over an unproven transport is refused
  **before** validation and **before** minting — assert both, not just the
  status.
- The anonymous `/v2/auth` mint behaves as the stated policy says, and the
  policy is written at the site.
- An **anonymous read** of `/v2/*` over plaintext is unaffected.
- `HORT_BEARER_ALLOW_OVER_HTTP=true` restores today's behaviour on both
  surfaces, and so does a declared waiver scope — with `transport` still
  reading `Unknown` in the waived case.
- A `docker`/`skopeo`/`podman` client flow in `scripts/native-tests/scenarios/clients/`
  still works under the compose opt-out; if the sandbox cannot run it, say so
  explicitly in the report and name the reason it would pass.
- Gate: `cargo test --workspace`, clippy, fmt last. No uncovered new lines.
