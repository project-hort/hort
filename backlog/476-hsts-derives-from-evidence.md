# 476 — HSTS derives from evidence, not from the address

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 5 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §2.2, §4.6. **Depends on 471.**
**Read first:** `crates/hort-http-core/src/middleware/security_headers.rs:30-60,125-160`.

## The defect

`security_headers.rs:158` emits `Strict-Transport-Security` when
`RequestTrust.public_url.scheme() == "https"`, and its module docstring calls
that *"positive evidence the public scheme is https"*. It is not evidence: the
same synthesis that made the credential gate unable to fire makes this
condition true for a plaintext request with a usable `Host` header, or for any
request at all when an `https://` base URL is pinned.

RFC 6797 §7.2: an HSTS host must not send `Strict-Transport-Security` over
non-secure transport. §8.1 means a user agent ignores one that arrives that
way, so **the practical exposure today is low** — this is a correctness and
consistency fix, and the unit should say so rather than overstate it. The
reason it is in scope at all: the decision on this issue is that an address
does not answer a transport question, and leaving one consumer reading the
address keeps the false inference alive in the module a reviewer will copy
next.

## What to build

- Emit HSTS when `transport == TransportSecurity::Tls` **and** the public
  origin is `https` (the second leg is what makes the header meaningful for
  the origin the client will revisit). `Unknown` and `Plaintext` emit nothing.
- Correct the module docstring: name the field it now reads and cite RFC 6797
  §7.2 as the rule. No issue references.
- Keep every other header in the module exactly as it is, including the
  `entry().or_insert_with` posture and the `Server` strip.

## Acceptance

- A request with `transport == Tls` and an `https` public origin gets HSTS,
  with the same value as today.
- A plaintext request with a usable `Host` gets **no** HSTS. Note which half of
  this is new: a **trusted** peer reporting `proto=http` also yields an `http`
  address, so it emitted none before either; an **untrusted** peer with a
  usable `Host` had `https` synthesised for its address while its evidence is
  `Unknown`, so it **did** get HSTS and now does not. Assert the second case —
  it is the one that changed, and it is the common direct-caller shape.
- A request with an `https`-pinned base URL but `transport == Unknown` gets no
  HSTS — a behaviour change, asserted deliberately.
- Absent `RequestTrust`: no HSTS.
- Every other header in the module is byte-identical, asserted.
- Gate: `cargo test --workspace`, clippy, fmt last. No uncovered new lines.
