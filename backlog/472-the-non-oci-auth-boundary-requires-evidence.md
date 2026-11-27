# 472 — the non-OCI auth boundary requires evidence

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 2 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §4.3, §4.4, §4.5, §8.
**Depends on 471.** The §3 decision is answered (a declared hop is
acceptable, as a **waiver** of the requirement), so nothing here waits.
**Read first:** `crates/hort-http-core/src/middleware/auth.rs`
(`require_principal`, `extract_optional_principal`, `resolve_token`,
`pat_over_http_decision`, the two shape matchers),
`crates/hort-http-core/src/router.rs:245-297`, the 471 derivation.

## The defect

Two halves of one boundary, both broken differently. On the **required** path
the refusal cannot fire, because its evidence is a synthesised address (471's
preamble). On the **optional** path there is no refusal at all:
`extract_optional_principal` (`auth.rs:458`) never calls it, and
`require_principal` (`auth.rs:311`) is its only caller. So a PAT, a CliSession
JWT or an IdP token presented on a read endpoint over plaintext is validated
and served, with no refusal and no signal to the client.

And the refusal's subject is a token **shape** —
`looks_like_pat_token` OR `looks_like_cli_session_jwt` (`auth.rs:1185`) — so an
IdP-issued access token is not covered on either path, while
`docs/auth-catalog.md` Entry 3 claims the gate covers "*any* bearer".

The two halves are one unit because they are one boundary: shipping one leaves
the predicate half-rewired and a reviewer holding two rules.

## What to build

1. **One verdict function in `hort-http-core`**,
   `credential_transport_verdict(trust: Option<&RequestTrust>, allow_over_http_unscoped: bool)
   -> CredentialTransportVerdict` with
   `Allowed | Waived(WaiverScope) | Refused(reason)`
   (design §4.3). It takes the extension lookup directly, so `None` cannot be
   forgotten at a call site and reads as `Refused`. Placed so
   `hort-http-oci` can consume the same definition in unit 473 (ADR 0008 puts
   inbound auth in both layers). Three values, not `Option`: `Waived` is
   counted and documented apart from `Allowed`, because it is the one condition
   an operator has to be able to see.
2. **Call it from both middlewares**, before any validation — mirroring
   `require_principal`'s current placement, which deliberately refuses before
   feeding a plaintext secret to the validator. On the optional path call it on
   the credential-present branches only (`TokenSource::Bearer`,
   `TokenSource::Basic`); `TokenSource::Absent` proceeds unchanged with
   `Option<AuthenticatedPrincipal> = None`.
3. **The subject becomes "a credential was presented"**: delete
   `looks_like_pat_token` and `looks_like_cli_session_jwt` — this decision is
   their only caller. An **anonymous** request is never refused.
4. **Same outcome on both paths**: `426` with `Upgrade: TLS/1.2, HTTP/1.1` and
   the existing body. Do not invent a read-path-specific behaviour such as
   ignoring the credential and serving anonymously — the credential is already
   on the wire, and a silent downgrade tells the client nothing about stopping.
5. **The refused read still audits**: the attempt metric and the
   `client_ip`-carrying `tracing::info!` fire as for any other outcome, so
   fail2ban and SIEM consumers see it.
6. **`hort_credential_transport_refusals_total{entry_point}`** for `require`
   and `optional`, registered in `docs/metrics-catalog.md` in this change
   (ADR 0017). The refusal `warn!` carries `evidence` and the trusted-peer
   fact.
7. **The waiver** (design §4.3.1), derived **once** in the trust middleware
   into `RequestTrust.tls_requirement_waived` beside `client_ip` — from the
   same socket address and the same config, never re-derived at a decision
   site. `HORT_TLS_NOT_REQUIRED_FROM`, a CSV of
   CIDRs matched against the **TCP peer** with the same IPv4-mapped
   canonicalisation `cidr_contains` applies, **default empty**, refusing
   `0.0.0.0/0` and `::/0` at boot, named in the boot log beside the existing
   trust summary. It **waives the requirement for that scope and never asserts
   that TLS happened.**

   **The precedence table of design §4.3.2 is the specification and is
   load-bearing.** A declared scope waives a request only when **all four**
   hold: evidence is `Unknown`; the peer is **not** a trusted proxy; the
   request is **not relayed** (no `Forwarded` and no `X-Forwarded-*` header
   present at all); and the raw TCP peer is inside the declared range.

   The not-relayed condition is the one that actually closes the ingress hole,
   so do not drop it as belt-and-braces: an ingress controller pod inside the
   waived range but **absent from `HORT_TRUSTED_PROXY_CIDRS`** is an untrusted
   peer whose forwarded scheme is ignored, so evidence is `Unknown` and the
   other three conditions hold — an external plaintext request through it would
   otherwise be waived, including on the mint surfaces. A waived peer must be
   the client, and a client that arrived through an L7 proxy carries that
   proxy's forwarding header; an L4 passthrough that adds none preserves the
   real source address, which is not inside a pod CIDR.

   `Plaintext` evidence is never waived by a scope either. The unscoped
   `HORT_BEARER_ALLOW_OVER_HTTP` keeps its current meaning and accepts
   regardless of evidence, peer or relay. Match on the **raw TCP peer**
   (`peer_ip`), never the XFF-derived `client_ip`; a missing `ConnectInfo`
   grants no waiver; a missing `RequestTrust` extension is `Refused` whatever
   the flag says.
   Never default it to loopback: a direct caller on the plaintext loopback
   listener would then be treated as protected, and a loopback peer may
   equally be a proxy that told us nothing (the shape this repo's Ansible
   templates ship). Add `hort_credential_transport_waived_total{entry_point,scope}`
   with `scope` ∈ {`declared`, `unscoped`}, in the metrics catalog in this
   change.
8. **`deploy/compose/docker-compose.yml` pins its network and declares it
   waived.** The file has **no `networks:` block**, so Docker picks the subnet
   from its address pool and there is no CIDR to declare — add an explicit IPAM
   subnet for the default network and render the **same value** into
   `HORT_TLS_NOT_REQUIRED_FROM`, with a comment in the invariant form (no issue
   references). The stack pins `HORT_PUBLIC_BASE_URL: "http://hort-server:8080"`
   (`:292`) and authenticates with IdP access tokens over plaintext; step 3
   makes every authenticated non-OCI client call `426` without this. Then
   **remove** the unscoped `HORT_BEARER_ALLOW_OVER_HTTP` from
   `docker-compose.native-tokens.yml:38-42` and
   `docker-compose.federation.yml:65-70` with their comments, so the scoped
   path is genuinely exercised instead of masked by the blunt flag. The
   declaration is true of this stack: TLS is not required on that network.
   The host-side `/auth/exchange` smoke
   (`scripts/host-tests/test-gitops-machine-identity.sh:385-393`, against the
   host-published port — the only end-to-end exchange flow in the tree) reaches
   the stack from outside it. **Measured on the host, 2026-11-25** (so the unit
   need not): a bridge with `subnet 10.247.72.0/24` gets gateway
   `10.247.72.1`, and a host→published-port connection arrives from
   `10.247.72.2` under podman's in-netns forwarder, or from the gateway under
   Docker's userland proxy. Both are allocated from the declared subnet, so a
   `/24` that *is* the network's subnet covers this peer by construction. If
   the smoke ever answers `426`, widen the declared value — do not re-add the
   unscoped flag — and read the actual peer off the trust layer's `debug!`
   line, which carries it.
9. **The structural guard** (design §8), function-scoped in the family of
   `crates/hort-app/tests/cas_reads_are_verified.rs` and
   `authorization_scheme_is_single_sourced.rs`: a credential decision reads
   `transport`, never a scheme. Scope the scan to credential-decision bodies in
   `hort-http-core` **and** `hort-http-oci`; **name the legitimate address
   reads explicitly** — the `debug!` at `trust.rs:284-289`, `url_resolver.rs`,
   and HSTS's origin check — because the invariant genuinely permits them.
   Assert the five-surface census calls the shared predicate. The surfaces that
   do not decide yet are declared in the guard as observing-only **with the
   durable reason** — each needs a refusal in an error envelope its own
   function does not build — and **not** with a unit number: a test file is
   code, and the no-tracker-references-in-code rule applies to it. The unit
   numbers belong in the commit message and the report. Mutation-check the
   guard by stripping one call from real on-disk source, in both directions
   (remove a decision; plant an address read).
10. **Catalog Entries 1, 2, 3, 4 and 8** in this same change (ADR 0018): each
    "in transit — TLS" line names what now enforces it, and Entry 3's gate
    description is corrected from a token shape to "any presented credential".

## Acceptance

- A credential on a **write** over an unproven transport is refused `426`; over
  `transport == Tls` it is accepted exactly as today.
- A credential on a **read** over an unproven transport is refused `426`; the
  same credential over `Tls` populates the principal as before.
- An **anonymous** read over plaintext is unaffected — assert it on an endpoint
  that serves anonymously today (ADR 0021).
- An **IdP access token** over an unproven transport is refused on both paths —
  it is not refused today on either.
- A refused read still emits the auth-attempt metric and the `client_ip` log
  line.
- `HORT_BEARER_ALLOW_OVER_HTTP=true` restores today's behaviour on both paths,
  and the gauge still reports.
- A peer inside `HORT_TLS_NOT_REQUIRED_FROM` is accepted on both paths with
  `transport` still reading `Unknown` — assert the field, not only the status:
  nothing may record that TLS happened. The request counts as
  `evidence=unknown` **and** `waived{scope="declared"}`.
- `GET /metrics` on the admin listener is enforced too — it is served through
  `require_principal` and differs only in its label (design §5.7). Pin both
  outcomes: refused without a declared hop, waived with one.
- **A peer inside the declared scope that is ALSO a trusted proxy is refused**,
  with no forwarded scheme present.
- **A peer inside the declared scope that is NOT a trusted proxy but sends any
  `X-Forwarded-For` / `X-Forwarded-Proto` / `Forwarded` header is refused** —
  the relayed row, and the one that closes the undeclared-ingress hole. Assert
  it for each of the three header names separately, and assert that a request
  with none of them from the same peer is waived.
- **A trusted peer reporting `X-Forwarded-Proto: http` is refused even when its
  address is inside the declared scope** — `Plaintext` is never waived by a
  scope.
- The waiver matches the raw TCP peer: a request whose XFF names an address
  inside the declared scope, from a peer outside it, is refused.
- A peer **outside** the declared scope is still refused, with the same
  declaration in place.
- Either wildcard in `HORT_TLS_NOT_REQUIRED_FROM` refuses to start, naming the
  variable; an IPv4-mapped IPv6 peer inside an IPv4 declared range is waived.
- The boot log names the declared ranges.
- The compose E2E (`./scripts/native-tests/run.sh --hort=compose --group clients`)
  passes — or, if no container runtime is available in the sandbox, the report
  states exactly that and names the flag as the reason it would pass. Do not
  claim a green E2E that was not run.
- The guard fails when a credential decision reads a scheme, passes with the
  named address reads present, and its mutation check goes red.
- Gate: `cargo test --workspace`, clippy, fmt last. No uncovered new lines.
