# 0063 — The operator declares which realms may receive an upstream credential

- **Status:** Accepted
- **Enforced by:** `RepositoryUpstreamMapping.allowed_realm_hosts` and the
  per-entry hostname rule
  `hort_domain::ports::repository_upstream_mapping_repository::allowed_realm_host_reason`,
  which the gitops validator **calls** rather than mirrors
  (`the_validator_and_the_constructor_share_one_realm_host_rule`). Four
  enforcement points: the apply-time validator
  (`hort_config::upstream_mapping::validate_allowed_realm_hosts`, reached from
  `desired::validate` and so from both `apply` and `validate-config`), the
  value object's constructor (also the read-path guard, since `row_to_mapping`
  goes through it), two schema CHECK constraints (migration `031`), and the
  runtime consent gate in `hort_adapters_upstream_http::fetch_with_challenge`.
  Regression tests: `a_credentialed_exchange_at_an_unlisted_realm_is_refused`
  (realm never called, and `SecretPort::resolve` called zero times, asserted at
  a counting port), `…_at_a_listed_realm_succeeds`,
  `an_anonymous_exchange_at_an_unlisted_realm_is_unchanged`,
  `a_listed_realm_host_matches_case_insensitively` (which also pins that a
  suffix is not a match), and the hop binding's
  `a_cross_host_hop_is_refused_when_the_client_presents_a_certificate`.
- **Supersedes:** —
- **Relates:** [0010](0010-no-insecure-tls-knobs.md) (the per-mapping TLS
  posture this complements — that one says *whom we trust*, this one says *whom
  we pay*), [0015](0015-apply-time-linter-inert-fields-and-naming.md) (a field
  accepted at apply must be load-bearing at runtime or rejected at apply),
  [0006](0006-mandatory-upstream-verification.md) (content verification, which
  is a different question from where a credential may travel),
  [0036](0036-oci-auth-capability-token.md) (the realm exchange's own
  protocol shape).

## Context

A `bearer_challenge` upstream mapping answers an unauthenticated request with
`401` and a `WWW-Authenticate` header naming a **realm**. Hort exchanges the
operator's credential there for a token, sending it as
`Authorization: Basic base64("oauth2:<secret>")`.

The realm is upstream-controlled data. Until this decision the only gates on it
were its scheme (`https`) and the routability of its resolved address — both
added for SSRF, neither saying anything about *who* may receive the credential.
A compromised or hijacked upstream could therefore answer `401` naming any
https, routable host and be handed the operator's credential for that mapping.

Binding the realm to the mapping's own origin is not available as a silent
default: a realm legitimately lives on another host — `auth.docker.io` for
`registry-1.docker.io`, GitLab's container registry at `/jwt/auth` on a
separate host. The question is therefore not derivable from the mapping; it has
to be *declared*.

## Decision

**The operator declares, per mapping, which hosts may receive that mapping's
credential. The mapping's own origin is always implicitly allowed and is never
listed.**

1. **The field** is `spec.allowedRealmHosts`, a list of **bare hostnames** — no
   scheme, no port, no path. The comparison is the host alone, ASCII
   case-insensitive, and a suffix is not a match. Hosts rather than origins,
   because an auth service legitimately differs from its registry in scheme,
   port and path, and the host is the party being paid.
2. **The gate binds to the credentialed exchange**: the realm must be allowed
   **iff** the exchange carries a credential. An anonymous exchange has nothing
   a nominated realm could receive, and every `bearer_challenge` mapping shipped
   in this repository is anonymous — four of them Docker Hub, whose realm is
   off-origin. A gate on every exchange would refuse those while protecting a
   credential that does not exist.
3. **Fail closed, before the credential is read.** A disallowed realm ends the
   exchange before `SecretPort::resolve` runs, so a refused realm causes no
   access to the operator's secret backend. An unparseable or host-less realm
   matches nothing: an allowance is something an operator wrote down, and a
   realm no host can be read out of is not something they could have written.
4. **The allowance covers one host, not wherever it redirects.** The exchange's
   redirect hops are bound to the allowed host, reusing the per-hop binding
   introduced for the per-mapping TLS identity. Without it the list is a front
   door with an open window: the allowed realm answers `302` and the credential
   travels on.
5. **Apply-time rejects what the runtime cannot enforce** (ADR 0015): a
   non-empty list on a mapping whose `auth.type` is not `bearer_challenge` is
   refused, and every malformed entry is reported, not just the first. A mapping
   **without** `secretRef` is **not** refused — the field's consumer comes into
   being the moment a secret is added to the same mapping, so it is conditional,
   not inert, and refusing it would force the credential and its allowance into
   two separate applies of which the first fails closed at fetch time.
6. **The refusal is the remedy.** Rejection messages state the accepted form
   with an example, and the runtime refusal logs the mapping and the **realm
   host** — the exact token the operator adds to the list. Path and query stay
   unlogged: they are upstream-controlled.

## Consequences

**No operator reconfiguration is required in the common case.** Only a mapping
that is *both* credentialed *and* has an off-origin realm needs an entry;
authenticated Docker Hub is the canonical one, and it needs a single line
(`auth.docker.io`). Nothing in this repository's gitops tree needed a change,
and the compose E2E was unaffected.

**For such a mapping the break is deliberate and visible**: the pull fails
closed with a server-side log line naming the host to add. There is no grace
period and no fallback to the previous behaviour — a fallback would be the
hole this decision closes.

**What this does not cover**, stated so it is not read as covered: a
credentialed exchange whose realm is the mapping's **own** origin consults no
allowance (the origin is implicit) and keeps whatever hop binding that
mapping's TLS material implies. `Authorization` is stripped by the HTTP client
across origins there, so the credential does not follow such a hop.

## Alternatives considered

**Bind the realm to the mapping's origin.** The simplest rule, and it breaks
the two most widely used registries. Rejected.

**Trust the first realm seen, per mapping.** Trust-on-first-use makes the
decision for the operator and makes it from upstream data. Rejected.

**A global allowlist.** The credential is per mapping, so the authorisation
belongs there; a deployment-wide list would let one mapping's upstream nominate
a host another mapping's credential then travels to. Rejected.

## References

- Issue #343 — audit #332 block 5, unit 8.
- `migrations/031_upstream_mappings_allowed_realm_hosts.sql`.
- `docs/architecture/how-to/declare-gitops-config.md` — the operator-facing
  field documentation; the apply-time row is in
  `docs/architecture/reference/apply-time-linter-rows.md`.
