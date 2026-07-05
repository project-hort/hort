# 0045 — OCI anonymous reads challenge before anti-enumerating; native-token parity under `BearerOnly`

- **Status:** Accepted
- **Enforced by:** the shared `read_denied_response` helper
  (`crates/hort-http-oci/src/middleware/oci_auth.rs`), invoked from every
  repo-level read-denial site — `manifests.rs`, `blobs.rs` (both the primary
  and the re-resolve-race arm), `tags.rs`, `referrers.rs` (both the primary
  and the step-3 race arm), `catalog.rs`. The helper's `AuthContext::Disabled`
  carve-out (`matches!(ctx.auth, AuthContext::Disabled)`) collapses every
  denial to the pre-existing `NAME_UNKNOWN` 404 regardless of `actor`. The
  consume-side middleware's fall-through uses `ctx.auth.authenticate()`
  (`Enabled | BearerOnly`) in place of the narrower
  `let AuthContext::Enabled { authenticate, .. } = &ctx.auth else` guard. The
  anonymous-write challenge lives in `oci_bearer_auth`'s `is_non_safe_method`
  branch, gated by the same `Disabled` carve-out. Regression tests: the
  per-endpoint `*_anonymous_denial_uniform_nonexistent_vs_private` and
  `*_authenticated_returns_404_name_unknown` groups in `manifests.rs` /
  `blobs.rs` / `tags.rs` / `referrers.rs` / `catalog.rs`;
  `read_denied_disabled_mode_returns_404_regardless_of_key`,
  `bearer_only_valid_pat_mints_principal`,
  `bearer_only_valid_svc_token_mints_service_account_principal`,
  `bearer_only_invalid_pat_returns_401`,
  `anonymous_post_upload_challenges_bearer_push_when_native_tokens_on`,
  `anonymous_post_upload_challenges_basic_when_native_tokens_off`, and
  `disabled_auth_anonymous_write_passes_through` in
  `middleware/oci_auth.rs`.
- **Supersedes:** —
- **Relates:** [0021](0021-read-handler-anonymous-by-default.md) (the
  anti-enum collapse this decision reuses and refines — not reopened),
  [0036](0036-oci-auth-capability-token.md) (the capability-token model this
  decision leaves unchanged — the cap/grants intersection is untouched),
  [0018](0018-auth-catalog-canonical.md) (`docs/auth-catalog.md` Entries 7/8
  updated in this same change, per the catalog's same-change rule).

## Context

Every OCI `/v2/*` read endpoint gates repo-level access through
`RepositoryAccessUseCase::resolve(.., AccessLevel::Read)`, which collapses
"repository does not exist" and "repository exists but is invisible to this
caller" into one `DomainError::NotFound` — the anti-enumeration shape
ADR 0021 mandates. Every handler mapped that `NotFound` straight to
`OciError::NameUnknown` (a 404), unconditionally, without regard to whether
the caller had presented a credential at all.

That is the wrong shape for a *credential-less* caller. Challenge-based OCI
clients — containerd's resolver in particular — request the manifest
directly with no prior `/v2/` ping and no credential; their authorizer only
engages when the server answers with `401` + `WWW-Authenticate`. A bare `404`
looks identical to "this repository does not exist," so the client's
imagePullSecret is never presented and a standard `docker pull` /
kubelet pull of a private image fails outright. Preemptive-Basic clients
(skopeo, after its own `/v2/` probe) worked around the gap, which is why it
survived end-to-end testing.

Two adjacent defects shared the same root cause — the consume-side
middleware and its anonymous-write path had not been updated in step with
each other:

- **Native-token validation hole under `AuthContext::BearerOnly`.** The
  middleware's fall-through to `AuthenticateUseCase::authenticate_bearer`
  matched only `AuthContext::Enabled`. Under `BearerOnly`
  (`HORT_AUTH_PROVIDER=disabled` + `HORT_NATIVE_TOKENS_ENABLED=true`) a
  directly-presented `hort_pat_*` / `hort_svc_*` on `/v2/*` was rejected at
  the middleware and never reached the PAT validator — even though the same
  validator routes PAT-shaped tokens correctly under `Enabled`.
- **Anonymous-write challenge not mode-aware.** An anonymous non-safe-method
  request (`POST`/`PUT`/`PATCH`/`DELETE`) on `/v2/*` fell through to the
  shared `hort-http-core` authz extractor's hardcoded `Basic realm="hort"`
  401, which advertises the wrong scheme whenever native tokens are wired.

## Decision

**Anonymous callers on a denied `/v2/*` read now see 401 + a mode-aware
`WWW-Authenticate` challenge instead of a bare 404; authenticated callers keep
the existing 404 anti-enumeration envelope. Native tokens presented directly
on `/v2/*` validate under `BearerOnly` exactly as they do under `Enabled`.
Anonymous non-safe-method requests are challenged with the same mode-aware
scheme. All three changes are inert under `AuthContext::Disabled`.**

### D1 — Uniform challenge-before-anti-enum on reads

| Caller | Repo | Before | After |
|---|---|---|---|
| anonymous | public | 200 / artifact-level flow | unchanged |
| anonymous | private, existing | 404 `NAME_UNKNOWN`, no challenge | **401 + `WWW-Authenticate`** |
| anonymous | nonexistent | 404 `NAME_UNKNOWN`, no challenge | **401 + `WWW-Authenticate` (byte-identical to the row above)** |
| authenticated, read granted | private | 200 / 503-quarantine | unchanged |
| authenticated, no read grant | private, existing | 404 `NAME_UNKNOWN` | unchanged |
| authenticated | nonexistent | 404 `NAME_UNKNOWN` | unchanged |
| invalid credential | any | 401 (middleware) | unchanged |

**Anti-enumeration equivalence.** Anonymous callers previously saw one
uniform response (404) over the set {private-existing, nonexistent}, and now
see one uniform response (401 + challenge) over the *same* set — the
partition of observable outcomes is unchanged, so ADR 0021's guarantee holds.
The challenge value carries only the caller's own request path echoed back as
`scope=`; it discloses nothing about which member of the set produced it.

The challenge value is the existing mode-aware selector: `Bearer
realm=<base>/v2/auth,service=<host>,scope=<path>` when `ctx.oci_signing_key`
is wired, else `Basic realm="hort"` — both carrying
`Docker-Distribution-API-Version: registry/2.0`.

### D2 — One shared denial helper, every repo-level read-denial site

`read_denied_response(ctx, actor, method, path, repo_key)` is the single
representation choice for a repo-level read denial: `actor.is_none()` (no
credential was ever presented — an *invalid* one already 401s at the
middleware) selects the challenge; `Some(_)` keeps the `NAME_UNKNOWN` 404.
Every site that previously mapped a repo-level `NotFound` straight to
`NameUnknown` now goes through this one helper. The use-case layer is
untouched: `RepositoryAccessUseCase::resolve`'s Read arm keeps collapsing
missing/invisible into one `NotFound` (ADR 0021's single-gate shape); the
HTTP representation choice moves to the handler, which already holds
`actor: Option<&CallerPrincipal>` in scope.

**`AuthContext::Disabled` carve-out.** In the open-registry / no-auth mode
the anonymous 401 + challenge is suppressed; every denial — anonymous or
not — returns the `NAME_UNKNOWN` 404. The challenge points at `/v2/auth`,
but under `Disabled` this middleware hard-rejects any presented token, so the
challenge could never be satisfied — advertising it would loop the client
forever. Disabled mode also admits every read at the RBAC layer, so the only
denial reachable under `Disabled` is a genuinely-absent repository, which the
404 already represents correctly. This mirrors the pre-existing `GET /v2/`
probe's own Disabled short-circuit.

### D3 — `BearerOnly` fall-through in the consume middleware

The middleware's guard for the native-token / IdP fall-through now uses
`ctx.auth.authenticate()`, which returns `Some(_)` for both `Enabled` and
`BearerOnly` (only `Disabled` yields `None`). A directly-presented native
`hort_pat_*` / `hort_svc_*` on `/v2/*` therefore reaches
`AuthenticateUseCase::authenticate_bearer`'s existing PAT branch under
`BearerOnly` exactly as it already did under `Enabled` — no new validation
logic, only a widened match arm. `Disabled` is unaffected: a presented token
is still rejected outright, never silently elevated.

### D4 — Mode-aware anonymous-write challenge at the OCI middleware

An anonymous (no `Authorization`) non-safe-method request on `/v2/*` (except
the path-skipped `/v2/auth`) is challenged at the OCI middleware with the
same mode-aware selector D1 uses, with `scope=` derived from the request path
via `path_to_scope` (`push` for uploads/manifest PUT, `delete` for DELETE).
Writes already required auth unconditionally, so this changes only the
challenge's scheme, never its presence. The `hort-http-core` shared authz
extractor's hardcoded `Basic realm="hort"` 401 remains the generic backstop
for non-OCI formats — it is simply unreachable for OCI writes once D4 is in
place. Under `AuthContext::Disabled` the write challenge is suppressed for
the same unsatisfiable-realm reason as D2; the request forwards with a `None`
principal exactly as before, and OCI writes are unreachable in production
under `Disabled` anyway (the boot gate rejects that provider/native-token
combination).

## Consequences

- A standard `docker pull` / kubelet pull of a private image — no prior
  `/v2/` ping, no credential on the first request — now receives a
  challenge it can act on, in both Basic mode and native-token mode. The
  imagePullSecret is presented and the pull succeeds.
- Basic mode is fully viable for private repositories: challenge → preemptive
  Basic → PAT validation, in both `Enabled` and `BearerOnly`. There is no
  need to deprecate or boot-warn Basic mode off private repos.
- A native token presented directly on `/v2/*` validates identically whether
  the deployment runs `Enabled` or `BearerOnly` — the two authenticated modes
  no longer diverge on this surface.
- Anonymous writes advertise the correct scheme in native-token mode instead
  of a stale `Basic` challenge.
- ADR 0021's anti-enumeration guarantee holds under the new representation —
  see the equivalence argument in D1.
- ADR 0036's capability model (mint carries `claims: []`, authority = grants
  ∩ cap, B1 fail-closed backstop) is untouched; this decision only changes
  which HTTP status/headers an anonymous denial produces and which auth
  modes accept a presented native token, never the authority computation
  itself.
- `AuthContext::Disabled` behavior is unchanged end to end: reads and writes
  keep their pre-existing representations, and no unsatisfiable challenge is
  ever emitted there.

## Alternatives considered

- **Deprecate Basic mode for private repos (the other of the two originally
  proposed fix directions).** Rejected: with D1–D4, Basic mode is fully
  functional for private repos in both auth modes, and containerd honours
  Basic challenges for imagePullSecrets just as well as Bearer ones. Boot-
  warning private repos off Basic mode would still have left the
  native-mode kubelet failure (the challenge gap, D1) unfixed — the two
  problems are orthogonal.
- **Anonymous token issuance at `/v2/auth` (Docker-Hub-style anonymous
  bearer minting).** Out of scope. hort serves public reads directly with
  200 and no challenge, so the anonymous-token dance this alternative would
  add is never required for the lazy-challenge clients this decision fixes.
  Revisit trigger: a ping-first client that eagerly fetches a token before
  every pull and fails on *public* repos in native-token mode because it
  never learns it didn't need one.
- **A new distinguishable `resolve()` outcome (e.g. a `DeniedAnonymous`
  variant alongside `NotFound`).** Rejected: it would push an
  HTTP-representation concern into the use-case layer and reopen ADR 0021's
  single-gate collapse for every read consumer. The handler already has
  `actor` in scope; the representation choice belongs there.
- **A config knob to disable the challenge.** Rejected: this is
  protocol-correct, secure-by-default behavior — there is no operator
  opt-in for it, matching the auth-catalog's secure-by-default posture
  (§1 of `docs/auth-catalog.md`).

## References

- `crates/hort-http-oci/src/middleware/oci_auth.rs` — `read_denied_response`,
  `unauthorized_response`, `v2_auth_challenge_value`, the `BearerOnly`
  fall-through, and the anonymous-write challenge branch in
  `oci_bearer_auth`.
- `crates/hort-http-oci/src/manifests.rs`, `blobs.rs`, `tags.rs`,
  `referrers.rs`, `catalog.rs` — the cut-over repo-level read-denial sites.
- `crates/hort-http-oci/src/version.rs` — the pre-existing `GET /v2/` probe
  challenge selector this decision's helper reuses (unchanged by this
  decision).
- `docs/auth-catalog.md` Entry 7 (challenge posture) and Entry 8 (the
  `/v2/*` consume surface, active under both `Enabled` and `BearerOnly`).
- [0021](0021-read-handler-anonymous-by-default.md) — the anti-enum
  collapse reused and refined here.
- [0036](0036-oci-auth-capability-token.md) — the capability-token model,
  unchanged.
- `docs/architecture/how-to/operate/oci-imagepull-secret-token.md` — the
  operator recipe for minting a least-privilege reader token that this
  decision makes work end to end against a kubelet/containerd pull.
