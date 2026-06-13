# 0010 — Centralised TLS construction; no insecure-TLS knobs

- **Status:** Accepted
- **Enforced by:** every adapter that opens TLS builds its client via `reqwest::Client::builder()` so the composition root can layer `apply_to_reqwest_builder` (system trust store + `HORT_EXTRA_CA_BUNDLE`) onto it. `reqwest::Client::new()` is architecturally forbidden in v2 adapters (review check). There is no `*_INSECURE_TLS` knob anywhere. (`cfg(test)` fixtures excepted.)
- **Supersedes:** —

## Context

"Just trust any certificate" toggles (`S3_INSECURE_TLS`, `LDAP_INSECURE_TLS`, `OIDC_INSECURE_TLS`, `HORT_TLS_INSECURE`, …) are the classic way operators defeat TLS to "make it work" against an internal CA — and the classic way MITM becomes possible in production. The legitimate need behind them is "trust our internal CA", which does not require disabling verification at all.

## Decision

All outbound TLS is verified against the **system trust store plus an operator-supplied CA bundle** (`HORT_EXTRA_CA_BUNDLE`). Every adapter that opens TLS constructs its HTTP client through `reqwest::Client::builder()` so the composition root can apply the shared trust configuration (`apply_to_reqwest_builder`); `reqwest::Client::new()` (which bypasses that layering) is forbidden in v2 adapters outside test fixtures.

**No `*_INSECURE_TLS` / verification-disabling knob exists**, for any subsystem (S3, LDAP, OIDC/JWKS, upstream fetches). The JWKS fetch path for OIDC issuers uses the same shared, verified client — there is no `insecure_jwks_url`.

## Consequences

- Internal/private CAs are supported the safe way: add the CA to `HORT_EXTRA_CA_BUNDLE`; verification stays on.
- It is not possible to ship a deployment that silently accepts any certificate.
- A new TLS-opening adapter must build via `builder()` and route through `apply_to_reqwest_builder`; `Client::new()` is a review finding.
- Re-introducing an insecure-TLS knob requires amending this decision first, not a code review waiver.

## Alternatives considered

- **Provide an insecure-TLS escape hatch "for dev/internal use".** Rejected: the escape hatch invariably reaches production, and the real need (internal CA trust) is served by `HORT_EXTRA_CA_BUNDLE` without disabling verification.
- **Let each adapter call `reqwest::Client::new()` and configure TLS ad hoc.** Rejected: the composition root then cannot guarantee the trust bundle is applied uniformly; centralised `builder()` layering is what makes the guarantee hold.

## References

- `apply_to_reqwest_builder` / `HORT_EXTRA_CA_BUNDLE` wiring; `crates/hort-adapters-oidc` `internal::build_http_client` for JWKS.
- The architect skill → anti-patterns *`reqwest::Client::new()` in any v2 adapter*, *reintroducing `*_INSECURE_TLS` knobs*, *`OidcIssuer` trusts an unverified JWKS*.
