# 0068 — Inbound credential transport requires evidence or a scoped waiver

- **Status:** Accepted
- **Enforced by:** `RequestTrust::transport` and `tls_requirement_waived` in
  `hort-http-core::middleware::trust`; the shared
  `credential_transport_verdict`; the non-OCI auth middlewares, OCI consume and
  mint handlers, token-exchange handler, and metrics listener that call it.
- **Relates:** [0010](0010-tls-builder-no-insecure-knobs.md) (outbound TLS),
  [0018](0018-auth-catalog-canonical.md) (inbound auth catalog),
  [0021](0021-read-handler-anonymous-by-default.md) (anonymous reads).

## Context

The public URL is an address for links and challenges. Its `https` default
does not establish how a request travelled. The server speaks HTTP behind an
operator-managed edge, so it cannot measure the client-to-edge TLS session
itself. A socket peer address identifies the immediate peer, not the
transport used before that peer.

Four established deployment shapes inform this decision: terminating TLS in
the process; accepting a scheme header only from a declared proxy and
distrusting its absence; qualifying a TLS requirement by caller scope; and
receiving measured transport state out of band. In the cited precedents,
none defaults missing transport evidence to `https`. Hort implements the
middle two shapes today.

## Decision

`RequestTrust::transport` carries `Tls`, `Plaintext`, or `Unknown`. Only a
declared trusted TCP peer's `Forwarded` or
`X-Forwarded-Proto` scheme can establish `Tls` or `Plaintext`. Every field
instance and list element is inspected. Conflicting, malformed, or
multi-element scheme claims yield `Plaintext`; a valid `Forwarded` field
without `proto` contributes no scheme claim. With no usable claim, or an
untrusted peer, the evidence is `Unknown`. The public URL and socket address
never supply TLS evidence. The edge must overwrite **both** header names
and prevent callers from reaching the listener around it.

Any presented credential, and any response that issues one, requires `Tls`
evidence or an applicable waiver. This covers non-OCI write and optional-read
auth, authenticated `/metrics`, OCI token consumption, `/v2/auth` issuance
including anonymous mint, and both token-exchange mint branches. Every
parsed token-endpoint request is checked before its parameters are validated.
Anonymous reads that neither present nor issue a credential remain available. A missing
`RequestTrust` refuses. The shared predicate returns `Allowed`,
`Waived(scope)`, or `Refused`; waivers never change the evidence value.

`HORT_TLS_NOT_REQUIRED_FROM` declares TCP peer CIDRs where TLS is not required.
It applies only to `Unknown` evidence for an untrusted, **unrelayed** peer.
A trusted proxy, any `Forwarded` or `X-Forwarded-*` header, and a trusted
proxy's `proto=http` cannot gain this waiver. Every caller able to reach the
socket from a declared range inherits it. `HORT_BEARER_ALLOW_OVER_HTTP` is the
legacy unscoped waiver for presented credentials and OCI minting; the token
endpoint explicitly forces that flag off. A direct plaintext token exchange
can use only the declared scope. **RFC 6749 §3.2 conformance is not claimed
for a request inside a waived scope.** The RFC puts the TLS obligation on the
authorization server for token-endpoint requests; the scope is an operator
exception, not proof that TLS occurred. When no declared scope applies, the
token endpoint admits only `Tls` evidence and the §3.2 requirement is
enforced; hort does not measure the session, so that conformance claim rests
on the edge preconditions stated above.

The eleven chart admin-task CronJobs call the plain HTTP Service URL and are
the worked example of a declared in-cluster hop. The chart exposes the
waiver range; it does not infer a portable pod CIDR. A loopback metrics
sidecar needs its own scope or TLS, and a loopback scope admits every process
sharing that network namespace. Network policy remains the control over who
can reach the socket from a waived range.

The exact `0.0.0.0/0` and `::/0` values are refused at boot for both proxy
trust and the scoped waiver. This is a tripwire for a common configuration
mistake, **not a security boundary**: equivalent CIDR unions cannot be
distinguished from the operator's deliberate declaration. The operator is
the trust authority.

`HORT_REQUIRE_HTTPS` is a boot-time configuration-consistency check, never
request evidence. Its implemented check rejects `HORT_PUBLIC_BASE_URL=http://…`
with no trusted-proxy CIDRs when enabled; an `https://` URL, a non-empty
trust list, **or an unset base URL** passes this check (other boot checks can
still fail). Passing this check does not prove
any request used TLS. HSTS is emitted only for `Tls` evidence together with
an `https` public origin.

## Consequences

The generic and OCI `426` refusal body now says `credential transport refused`
instead of `pat over http refused`, because the refused credential need not
be a PAT and `Unknown` need not mean HTTP. The token endpoint keeps its
OAuth-shaped `error_description`. The earlier generic `warn!` text changed
from `bearer-over-HTTP refused` to `credential transport refused`; consumers
matching either old string must update their alerts. All refusals carry
`Upgrade: TLS/1.2, HTTP/1.1`.

`hort_credential_transport_total{entry_point,evidence}` counts actual
evidence; `hort_credential_transport_refusals_total{entry_point}` covers all
six route classes; and `hort_credential_transport_waived_total{entry_point,scope}`
separates declared and unscoped waivers. The generic auth middleware also
emits `hort_auth_attempts_total` and attempts a best-effort auth audit event
on its refusals. The
OCI subtree has never emitted those auth streams, so its transport counter
and warning are the complete refusal signal there. The trust-layer `debug!`
line includes the raw socket `peer`; metric labels contain no address.

## Alternatives considered

- **Make the public address honest.** It would repair the security predicate
  by publishing plaintext redirects, links, and OCI realms to clients.
- **Use one global declaration.** It would waive unrelated external callers;
  the actual plaintext hop has a peer scope.
- **Require TLS on every credentialed request.** This narrows who can assert
  the transport but does not let hort measure TLS: it moves the assertion
  from configuration to a proxy header. The scoped plaintext topology is an
  accepted operator decision.
- **Withdraw the inbound TLS claim.** This would be honest outside the token
  endpoint, but leave credential-bearing paths without the chosen guard.

## Future evidence sources

In-process TLS termination and PROXY protocol v2 TLS information are designed
for as possible measured sources. Neither is implemented. Client-certificate
identity and the OCI subtree's broader audit posture are separate decisions.

## References

- [RFC 6749 §3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)
- [RFC 7239 §§4, 7.1](https://www.rfc-editor.org/rfc/rfc7239)
- [RFC 6797 §7.2](https://www.rfc-editor.org/rfc/rfc6797#section-7.2)
- [Keycloak SSL modes](https://www.keycloak.org/docs/latest/server_admin/index.html#_ssl_modes)
- [PostgreSQL `hostssl` / `hostnossl`](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [Vault TLS listener](https://developer.hashicorp.com/vault/docs/configuration/listener/tcp)
- `docs/auth-catalog.md`; `docs/metrics-catalog.md`
