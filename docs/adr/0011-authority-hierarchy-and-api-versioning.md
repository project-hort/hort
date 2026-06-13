# 0011 — Authority hierarchy, and first-party API versioning

- **Status:** Accepted
- **Enforced by:** convention + review (the authority hierarchy is a process rule); the API-version rule is structural — the first-party REST surface is nested under `/api/v1`, while protocol-mandated `/v2/...` paths (OCI Distribution Spec) are a separate, untouchable namespace.
- **Supersedes:** —

## Context

The codebase has multiple sources of truth that can disagree: official protocol specs, the design documents, the existing implementation, and the existing tests. The entire prototype was machine-generated and is a *behavioural reference*, not ground truth — passing E2E tests prove self-consistency, not protocol correctness. Without an explicit ranking, an implementer can "cite the code" to justify a protocol violation.

Separately, the prototype's REST surface lived at `/api/v1` and the rewrite's at `/api/v2` — but `/api/v2` was only ever an *intra-repo discriminator* to avoid colliding with the prototype's routes in the same binary. It was never a public API version.

## Decision

**Authority hierarchy** (highest to lowest): (1) official protocol specifications; (2) `docs/auth-catalog.md` for inbound-auth conflicts; (3) the design documents (ADRs and active design docs); (4) the implementation (reference only); (5) the tests (reference only). Where the implementation conflicts with a spec or design document, the spec/design wins and the divergence is a prototype bug, not a requirement.

**First-party API versioning:** the first-party REST surface ships at **`/api/v1`** — the honest first version of a fresh product. Protocol-mandated version segments are orthogonal and **not ours to renumber**: the OCI Distribution Spec's `/v2/...` (registry root, `/v2/auth`) stays exactly as the spec dictates. The discriminator is the `/api/` prefix — `/api/vN` is first-party; bare `/vN` is protocol.

## Consequences

- A future contributor cannot "helpfully" renumber OCI's `/v2` to match the first-party `/api/v1` — protocol paths are off-limits.
- "The code does X" is not a defence for X violating a spec; the divergence gets fixed, and the design document amended if it was wrong.
- The first public API version is `/api/v1`, with no vestigial `/api/v2` implying a second version that never existed.

## Alternatives considered

- **Ship the first-party surface at `/api/v2`** (keep the discriminator). Rejected: a brand-new v1 product whose endpoints all claim version 2, for no reconstructable reason — the same incoherence inverted.
- **Treat the implementation as ground truth** (it passes tests). Rejected: the tests are AI-generated and prove self-consistency, not protocol compliance; the spec must outrank the code.

## References

- `crates/hort-server/src/http.rs` — first-party `/api/v1` nest; `crates/hort-http-oci` — protocol `/v2`.
- CLAUDE.md → "Architectural Direction" (authority hierarchy); `docs/auth-catalog.md`.
