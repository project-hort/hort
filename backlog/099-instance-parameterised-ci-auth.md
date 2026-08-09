# 099 — Instance-parameterised CI auth: separate build source from warm target

**Issue:** #139 (items A, B, C) · **Branch:** `agent/139-instance-parameterisation` · **Scope:** `.gitlab-ci.yml`

## Why

`.gitlab-ci.yml` assumes a single hort instance. `HORT_URL` is not declared
anywhere; the auth anchor simply falls back to `https://registry.hort.rs`, and
the same minted token serves both roles a pipeline actually has:

- **build source** — the instance cargo/npm/the OCI client resolve from, and
- **warm target** — the instance whose proxy gets warmed for a later release.

The target state needs those to differ (feature/develop build against the
internal instance while develop warms the public one), which is not expressible
today. This item makes it expressible **without changing any behaviour**: every
new variable defaults to the current value.

## Change

**A — the anchor becomes instance-parameterised.**

- Declare `HORT_BUILD_URL` (default `https://registry.hort.rs`) — the instance
  whose cargo/npm/OCI configuration the anchor writes.
- Declare `HORT_WARM_URL` (default `https://registry.hort.rs`) — the instance
  the prefetch jobs POST to.
- The anchor's exchange + tool configuration keys off `HORT_BUILD_URL`.
  Keep `HORT_URL` honoured as a fallback for both if set, so an operator
  who sets it today is not silently ignored; document that it is deprecated in
  favour of the two explicit variables.
- The two roles need **separate exchanges** when the URLs differ: different
  instances mean different service accounts and audiences, so a token minted
  against one is not valid at the other. When the URLs are equal (the default),
  mint once and reuse — a pipeline against a single instance must not pay for
  two exchanges.

**B — the prefetch jobs target the warm instance.** `prefetch:warm` and
`prefetch:verify` use `HORT_WARM_URL` and its token, not the build source's.

**C — remove the last hardcoded-host mention.** The descriptive comment on the
`.docker` anchor still names `hort.kdp.kloni.cloud` in prose. Reword it to name
the variable instead. Cosmetic, but it is the last literal.

## Out of scope

Switching any default to the internal instance (issue #139 items D/E) — those
wait on operator prerequisites that cannot be verified from this repository.
This item only makes the switch *possible*.

## Acceptance

- Defaults unchanged ⇒ a green pipeline is the proof: the same exchange, the
  same warm, the same 692 enqueued deps as today.
- `prefetch:warm`'s log still shows `token exchange succeeded` and
  `HORT_PROXY_ENABLED != 'true' — dependency sources unchanged`.
- Setting `HORT_BUILD_URL` and `HORT_WARM_URL` to different values produces two
  exchanges; setting neither produces exactly one. Demonstrate the branch
  logic with a shell-level test rather than a live pipeline against two
  instances.
- No hardcoded registry host remains outside a variable definition.
