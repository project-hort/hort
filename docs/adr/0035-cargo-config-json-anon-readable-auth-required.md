# ADR 0035 — cargo `config.json` anonymously readable; advertises `auth-required`

- **Status:** Accepted
- **Enforced by:** `RepositoryAccessUseCase::find_by_key_unchecked` in
  `crates/hort-app/src/use_cases/repository_access.rs`; handler comment in
  `crates/hort-http-cargo/src/lib.rs::config_json`; regression test
  `sparse_index_private_repo_anon_still_returns_404`.
- **Fixes:** GitLab issue #1 — gated cargo proxy unreachable by `cargo build`.
- **Cross-references:** ADR 0021 (read handlers anonymous-by-default; the
  visibility gate), RFC 3231 (cargo `auth-required`), auth-catalog Entry 8
  (HTTP Basic carrier — the mechanism cargo uses once it learns `auth-required`).

## Context

Cargo (RFC 3231) fetches `config.json` anonymously to learn the `auth-required`
field before deciding whether to attach its configured registry token to index
and download requests.  Critically, if `config.json` responds with a 404 or
401, cargo does NOT retry the request with a token — it fails immediately with
`error: config.json not found in registry`.

Before this ADR, the `config.json` handler resolved through
`RepositoryAccessUseCase::resolve(.., AccessLevel::Read)`, which collapses
missing-repo and invisible-private-repo into the same `NotFound` envelope
(anti-enumeration, ADR 0021).  For a gated (`is_public: false`) cargo proxy
repo, anonymous callers receive a 404, and cargo cannot bootstrap — the token
is never sent and every index/download request returns `NotFound`.

## Decision

Make the cargo `config.json` endpoint **anonymously readable** and advertise
**`auth-required: !is_public`**.

The index and download endpoints (`sparse_index`, `sparse_index_4plus`,
`download`) are **unchanged** — they continue to go through
`resolve(.., AccessLevel::Read)` and return `NotFound` to anonymous callers on
private repos.

`config.json` now uses `RepositoryAccessUseCase::find_by_key_unchecked`, which
returns the full `Repository` with no visibility gate.  A genuinely missing repo
still returns 404; an existing private repo returns 200 with
`"auth-required": true`.

## Anti-enumeration trade-off (bounded give-up)

This decision deliberately reverses the `config.json` anti-enumeration posture
documented in the previous handler comment.  The give-up is bounded:

| Surface | Before | After |
|---|---|---|
| `config.json` — private repo exists | 404 (anti-enum) | 200 + `auth-required: true` |
| `config.json` — genuinely missing repo | 404 | 404 (unchanged) |
| Sparse index — private repo, anon | 404 (anti-enum) | 404 (UNCHANGED) |
| Download — private repo, anon | 404 (anti-enum) | 404 (UNCHANGED) |

The leak is: *repo existence + dl/api URLs + "auth is required"*.  No crate
content (index entries, tarball bytes, checksums) is revealed.  For cargo proxy
repos, the upstream is a public registry (crates.io); the fact that a private
hort mirror of crates.io exists is not a meaningful secret.

## Rejected alternatives

**2b — Uniform 401 challenge + cargo retry.** RFC 3231 specifies that cargo
reads `auth-required` from `config.json` and sends the token from that point
forward.  Cargo does NOT implement a 401-challenge→retry loop for `config.json`
itself; a 401 produces the same dead-end as a 404.  This alternative cannot
work without changes to the cargo client.

## Scope — npm and pypi unaffected

This decision is cargo-specific.  Neither npm nor PyPI has the conditional-token
bootstrap gap:

- **npm** (`hort-http-npm`): the npm client sends `Authorization: Bearer
  <_authToken>` on every request if a token is configured for the registry.
  There is no discovery step that preconditions the token.
- **PyPI** (`hort-http-pypi`): pip/Poetry authenticate via URL-embedded
  credentials or `~/.netrc`; the credentials are attached to every request from
  config.  There is no RFC-3231-equivalent conditional-send mechanism.

No code change is needed in `hort-http-npm` or `hort-http-pypi`.

## `find_by_key_unchecked` call-site discipline

`RepositoryAccessUseCase::find_by_key_unchecked` is documented as the
anti-enum-exempt lookup for format config/discovery bootstraps only.  It MUST
NOT be used for content endpoints (index, tarballs, manifests, blobs) — those
must continue to use `resolve(.., AccessLevel::Read)`.  The method's rustdoc
states this constraint explicitly.

## Test evidence

- `config_json_private_repo_anon_returns_200_with_auth_required_true` — 200 +
  `auth-required: true` on an anonymous request to a private cargo repo.
- `config_json_public_repo_anon_returns_200_with_auth_required_false` — 200 +
  `auth-required: false` on a public repo.
- `config_json_unknown_repo_returns_404` — genuinely missing repo → 404.
- `sparse_index_private_repo_anon_still_returns_404` — regression guard:
  `sparse_index` on a private repo returns `NotFound` for anon callers (gating
  preserved).
- `anti_enumeration::config_json_private_repo_returns_200_with_auth_required` —
  in the `anti_enumeration` module: private-repo 200 + `auth-required`, missing-
  repo still 404.
- `find_by_key_unchecked_returns_private_repo`,
  `find_by_key_unchecked_missing_repo_returns_none`,
  `find_by_key_unchecked_propagates_port_error` — hort-app unit tests.
