# 471 — transport evidence is its own field, observed before it is enforced

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 1 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §4.1, §4.2, §4.7 (revision 2).
**Read first:** `crates/hort-http-core/src/middleware/trust.rs` (all of it —
`evaluate_trust`, `resolve_public_url`, `forwarded_proto`, the XFF walk,
`cidr_contains`), `crates/hort-server/src/config.rs` (the CIDR parse, the
boot-gate error style), `docs/metrics-catalog.md` (label schema and
cardinality rules), ADR 0017.

**This unit changes no decision anywhere.** It adds the evidence, derives it
strictly, counts it, and stops. That is deliberate: it is what lets an operator
measure whether the later refusal would bite their deployment *before* it
does, and it is why it carries no operator configuration at all.

## The defect it prepares for

`pat_over_http_decision` (`middleware/auth.rs:1184`) asks whether the request
arrived over TLS and reads `RequestTrust.public_url.scheme()`, which
`resolve_public_url` synthesises: a pinned `HORT_PUBLIC_BASE_URL` wins over
everything, a trusted peer's absent `X-Forwarded-Proto` defaults to `https`,
and an untrusted peer with a usable `Host` is hardcoded `https`
(`trust.rs:357-407`). Where the address is `https`-shaped the predicate
reports TLS proven for every request, including one that reached the plaintext
listener past the proxy.

## What to build

1. **`TransportSecurity { Tls, Plaintext, Unknown }`** and
   `RequestTrust.transport` (design §4.1). Document on the type that it carries
   evidence only and that `Unknown` is never lenient. The sibling field
   `tls_requirement_waived` belongs to unit 472 — this unit adds the evidence
   only, so nothing here can accept what it would not have accepted before.
2. **`resolve_transport_security`**, the strict derivation of design §4.2 step
   1 — and **only** step 1 in this unit:
   - gate on the existing `peer_trusted` CIDR check, with the same
     IPv4-mapped canonicalisation `cidr_contains` already applies
     (`trust.rs:410-423`);
   - collect **every** value of `Forwarded` (RFC 7239 `proto=`) and
     `X-Forwarded-Proto` — repeated header fields *and* comma-separated element
     lists. `HeaderMap::get` sees one value (`trust.rs:425-430`); use
     `get_all` and split elements;
   - all `https` → `Tls`; all `http` → `Plaintext`; **disagreement, a
     malformed value, or more than one element → `Plaintext`** (ambiguity
     denies — this is what makes a forged `Forwarded` beside a correctly
     overwritten `X-Forwarded-Proto` deny rather than pass); none present →
     `Unknown`.
   - There is deliberately **no precedence order** between the two header
     names. Do not add one.
3. **Leave `resolve_public_url` byte-for-byte as it is.** Its `https` default
   is correct for an address. Do not "fix" it, and do not route it through the
   new function.
4. **Two boot refusals**: `HORT_TRUSTED_PROXY_CIDRS` rejects `0.0.0.0/0` and
   `::/0`, as a new `ConfigError` in the existing message style. Prose already
   advises against it (`config.rs:1630`) and the parser accepts it
   (`config.rs:3404-3425`). The waiver variable unit 472 introduces carries the
   same refusal in its own unit — not here.
   State at the site what the refusal is: a tripwire for the documented
   copy-paste, not a boundary — `0.0.0.0/1,128.0.0.0/1` is equivalent and
   nothing can stop it, because the operator is the trust authority.
5. **`hort_credential_transport_total{entry_point,evidence}`** — incremented
   for every request that presents a credential (an `Authorization` header that
   resolves to a token, or a `subject_token` form field) or would issue one,
   across all five surfaces of design §2.3, **with no refusal anywhere**.
   `entry_point` ∈ {`require`, `optional`, `metrics`, `oci_consume`,
   `oci_mint`, `exchange`}, `evidence` ∈ {`tls`, `plaintext`, `unknown`}.
   `metrics` is `GET /metrics` on the **separate admin listener**
   (`hort-server/src/http.rs:359-436`), which applies `require_principal` and
   `request_trust` of its own and is not routed through
   `method_based_auth_dispatch` — it is the same consumer by another route and
   needs its own label, because the chart binds that listener to loopback for a
   sidecar scrape. Register the metric **and** both label value sets in
   `docs/metrics-catalog.md` in this change (ADR 0017).
6. Carry the trusted-peer fact where the later refusal log needs it: either on
   `RequestTrust` or recomputed at the trust layer. Do not plan to invent it
   inside a predicate that only sees `transport`.
7. **Add the raw socket `peer` to the trust layer's existing `debug!`**
   (`trust.rs:283-289`, which today logs the *derived* `client_ip` — a
   different value behind a proxy). This is the only instrument that answers
   "which peer does hort actually observe for this caller", and an operator
   needs it before choosing a waiver range in unit 472/478: the metrics carry
   `entry_point` and `evidence` and no address. Keep it at `debug` — it is a
   per-request address and does not belong at `info`.

## Acceptance

- An untrusted peer with only a `Host` header yields `Unknown`; the same
  request with `X-Forwarded-Proto: https` still yields `Unknown`.
- A trusted peer with no forwarded header yields `Unknown` — **not** `Tls`.
- A trusted peer with `X-Forwarded-Proto: https` yields `Tls`; with `http`,
  `Plaintext`; with `Forwarded: proto=https`, `Tls`.
- **Two header fields that disagree yield `Plaintext`**, in both orders, and a
  repeated `X-Forwarded-Proto: https` + `X-Forwarded-Proto: http` does too.
- A `Forwarded` element list with two entries yields `Plaintext`.
- A malformed `Forwarded` value yields `Plaintext`, not `Unknown`.
- A **valid** `Forwarded` field with no `proto` parameter is **not** malformed:
  it contributes no scheme, so the verdict comes from the remaining values and
  is `Unknown` when there are none (RFC 7239 §4 makes `proto` optional).
- **Two same-name fields that agree still yield `Plaintext`** — an element
  beyond the one the immediate trusted proxy wrote is an upstream hop with no
  trust relationship, and the operator contract requires the edge to overwrite
  rather than append (RFC 7239 §7.1).
- An IPv4-mapped IPv6 peer inside an IPv4 trusted CIDR is treated as trusted,
  matching `cidr_contains`.
- Absent `RequestTrust` reads as `Unknown` wherever the field is consulted.
- `public_url`, every emitted URL and the HSTS condition are **unchanged** —
  assert HSTS still rides on the address in this unit.
- Either wildcard in `HORT_TRUSTED_PROXY_CIDRS` refuses to start, naming the
  variable.
- The counter fires on all six route classes with the right `entry_point`,
  including a scrape of the admin listener, and
  **no request is refused by this unit** — assert a plaintext credential still
  succeeds exactly as before.
- `docs/metrics-catalog.md` carries the metric and both label sets.
- The trust `debug!` carries both the raw `peer` and the derived `client_ip`,
  and they differ in a test with a trusted proxy and an `X-Forwarded-For`.
- Gate: `cargo test --workspace`, clippy, fmt last. No uncovered new lines.
