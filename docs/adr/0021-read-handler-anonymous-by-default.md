# 0021 — Read handlers are anonymous-by-default; per-resource visibility is the only gate

- **Status:** Accepted
- **Enforced by:** the global method-based auth layer sends every `GET`/`HEAD`/`OPTIONS` through `extract_optional_principal` (anonymous allowed) and only non-safe methods through `require_principal`. There is **no middleware defence-in-depth for reads** — so a read use case is a review hard-block unless it threads the caller and enforces per-resource visibility itself.
- **Supersedes:** —

## Context

Registry reads must serve anonymous public traffic for public repositories, so safe methods cannot be blanket-gated at the middleware. The consequence is sharp: the middleware lets every read through as (possibly anonymous), and the **use-case per-resource visibility filter is the only authz gate** for reads. A read handler that forgets to thread and enforce the caller is therefore silently **world-readable** — it returns data, not a 403, with nothing in front of it.

This already bit once: the notification path delivered privileged-category events with no category-admin gate, precisely because of anonymous-by-default delegation.

## Decision

Every read use case / read endpoint takes the caller (`Option<&CallerPrincipal>` or the established caller type) **and enforces per-resource visibility itself**. A read path that does not thread and enforce the caller is a hard block in review — unless it is a deliberately-anonymous path registered in `is_anonymous_path` with a recorded rationale. A denial path (or `NotFound` anti-enumeration collapse) must be exercised by a test.

## Consequences

- New read code is presumed world-readable until proven gated; the reviewer's default is suspicion, not trust.
- The per-resource filter is load-bearing and must be tested, not assumed.
- This is an architectural blast-radius rule for *future* read code; the audited handlers thread the caller correctly today and `is_anonymous_path` is robust, so it is not an active vuln — it is the guard against the next one.

## Alternatives considered

- **Add middleware-layer authz for reads too (defence in depth).** Rejected: blanket read-gating breaks anonymous public-repo serving, which is a hard requirement; the per-resource filter is the right granularity.
- **Treat reads as low-risk and skip caller threading.** Rejected: that is exactly the footgun that bit the notification path — anonymous-by-default makes a forgotten caller a silent data leak.

## References

- `crates/hort-http-core/src/router.rs` (method-based auth split); `is_anonymous_path`.
- `docs/architecture/how-to/add-a-format-handler.md` (architectural-risk note).
- The architect skill → the read-handler review checklist.
