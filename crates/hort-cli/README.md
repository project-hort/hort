# hort-cli — Command-Line Client

## What this binary IS

- A pure HTTP client: zero dependency on `hort-domain`, `hort-app`, or
  `hort-adapters-*` — enforced by the dep graph and verifiable with `cargo
  tree -p hort-cli`. `[dependencies]` is `reqwest` + `clap` + `tokio` +
  `serde`/`toml` + `tracing` + `hort-attribution` and similar leaf
  utilities, nothing from the domain/app/adapter layers.
- The operator/developer CLI: `auth`, `admin`, `get`, `curation`,
  `list-versions`, `prefetch`, `completions`, `license`, `attribution`
  subcommands (the `Commands` enum).

## Session / token handling

Login supports RFC 8628 device-flow, RFC 8252 loopback, and paste-token
flows, with server-config auto-discovery. **Token storage is a plaintext
`token` field in `~/.hort/config.toml`** (resolution precedence: CLI flag
> env var `HORT_TOKEN` > config file), not an OS keychain — do not assume
keychain-backed storage when writing docs or support guidance for this
crate. Session lifetime itself is governed by ADR 0013 (short-lived,
IdP-backed, ≤1 h for admin-capable sessions) — that ADR governs token
*lifetime*, not *storage location*; the two are separate facts.

## Entrypoint

`main()` runs `clap_complete::CompleteEnv::with_factory(...).complete()`
**before** building any tokio runtime (a nested `block_on` would otherwise
panic), then builds a `current_thread` runtime and dispatches each
`Commands` variant to its module's `run()`. Tracing clamps `reqwest`/`hyper`
to `warn` to avoid leaking bearer tokens via debug logs.

## Quickstart

```bash
hort-cli auth login --paste
# Paste a hort_svc_*/hort_cli_* token at the prompt.

hort-cli get pypi-dev/some-package
```

## Rules

- Zero `hort-domain`/`hort-app`/`hort-adapters-*` dependency is a structural
  isolation guarantee, not a convention — verify with `cargo tree -p
  hort-cli` before adding any new dependency to this crate.
