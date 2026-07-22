# hort-net-egress — SSRF Egress Predicate

## Layer

Outbound adapter (nominally) — but structurally a **zero-dependency shared
primitive** one layer below the adapter mold, not a port implementation.
The crate's own doc comment makes this a structural rule: it does not
depend on `hort-domain`, `hort-app`, or any `hort-adapters-*` crate, and its
`[dependencies]` section is empty. Re-introducing such a dependency is a
structural review block. Requires >= 85% coverage.

## Responsibility

Hosts the single canonical `is_routable(ip: IpAddr) -> bool` SSRF
block-list predicate (loopback/link-local/RFC1918/CGNAT/documentation
ranges, for both IPv4 and IPv4-mapped-or-compatible IPv6), consumed at
URL-input-validation time by every adapter that fetches
attacker-influenceable URLs (e.g. `hort-adapters-upstream-http`,
`hort-notifier-webhook`).

## Ports

- **Implements:** none — no port trait, by design; `is_routable` is a free
  function, not a trait implementation.
- **Consumes:** none — zero dependencies, by charter.

## Key types

- `is_routable(ip: IpAddr) -> bool` — the crate's sole public export.

## Rules

- Zero dependencies on `hort-domain`/`hort-app`/`hort-adapters-*` is a
  structural review block if violated, not a style preference — this
  crate is deliberately minimal so every SSRF-relevant adapter can share
  one audited predicate rather than reimplementing it. An earlier, larger
  surface (a `GuardedDnsResolver` / egress-redirect-policy / allowlist
  helper) was deliberately removed after the EGRESS-1 posture was
  re-evaluated; this crate stays intentionally small by decision, not
  oversight.
