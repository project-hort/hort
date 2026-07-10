# 0047 — Dual-license `MIT OR Apache-2.0`; generated, CI-verified third-party attribution

- **Status:** Accepted
- **Enforced by:** the `security:attribution-sync` job (`.gitlab-ci.yml`) + mirrored
  `attribution-sync` job (`.github/workflows/ci.yml`, in `ci-complete`'s blocking
  set), both running `scripts/check-attribution.sh` — which regenerates the
  committed `THIRD-PARTY-LICENSES.{md,json}` with `cargo-about` (config `about.toml`),
  `git diff --exit-code`s them, and asserts `about.toml` `accepted` == `deny.toml`
  `[licenses] allow`. The `hort-attribution` leaf crate's zero-dependency shape is
  guarded by `cargo tree -p hort-cli` (adding a `hort-*` lib there would break the
  ADR-0008-adjacent hort-cli isolation). Out-of-allowlist inbound licenses are
  caught by the separate `cargo deny check licenses` gate.
- **Supersedes:** —
- **Relates:** [0009](0009-least-privilege-runtime-migrate-subcommand.md) (the
  `license`/`attribution` subcommands are DSN-free print-and-exit, per its
  DB-free-subcommand principle), [0017](0017-metrics-catalog-canonical.md) /
  [0018](0018-auth-catalog-canonical.md) (the canonical-file + same-PR-review gate
  pattern this reuses for attribution).

## Context

hort was MIT-only (`workspace.package.license = "MIT"`), silent on patents, and
shipped **no** third-party attribution despite compiling in ~480 permissively-
licensed crates and bundling external tools (Trivy, osv-scanner, tini) in its
images. Two gaps: (1) Apache-2.0 §3's explicit patent grant + retaliation clause
that enterprise legal review of a supply-chain tool often expects was absent; (2)
distributing binaries built from permissive crates carries an attribution duty
(Apache-2.0 §4 / BSD) that nothing satisfied. Adding Apache-2.0 is free now (single
author, no contributor consent needed); after external MIT-only contributions land
it would need every contributor's sign-off.

## Decision

**Adopt the Rust-ecosystem dual license `MIT OR Apache-2.0`, generate the
compiled-in third-party attribution from the actual dependency graph and CI-verify
it, keep image-bundled-tool attribution a separate surface, and expose both through
DSN-free `license`/`attribution` subcommands on all three binaries.**

### D1 — Dual license

`workspace.package.license = "MIT OR Apache-2.0"` (all crates inherit); `LICENSE`
split into `LICENSE-MIT` + verbatim `LICENSE-APACHE`; README + both OCI
`org.opencontainers.image.licenses` labels + the inbound-contribution note updated.
The `OR` is a grant of options (consumer chooses), not a double obligation — it
strictly widens adoption (GPLv2 consumers take MIT; patent-conscious enterprises
take Apache-2.0). MIT is retained.

### D2 — Generated, CI-verified attribution in a zero-dep leaf crate

Because `hort-cli` is a deliberately isolated pure-HTTP client (zero
`hort-domain`/`hort-app`/`hort-adapters-*` deps), the shared implementation lives in
a **new zero-`hort-*`-dependency leaf crate `hort-attribution`** — putting it in a
domain/app crate would break that isolation. `cargo-about` (`about.toml`, `accepted`
== the `deny.toml` allowlist) generates `THIRD-PARTY-LICENSES.md` (human) +
`.json` (`[{name,version,url,spdx,license_text}]`), committed at the repo root and
embedded via `include_str!`. The CI gate regenerates + diffs (staleness) and asserts
`about.toml` == `deny.toml` allow (completeness). Regeneration is deterministic
(the regen script normalises CRLF + strips the JSON trailing comma so the diff is
apples-to-apples across OSes).

### D3 — Image NOTICE is a separate surface

External tools baked into the *images* (Trivy Apache-2.0, osv-scanner Apache-2.0,
tini MIT, distroless base contents) are **not** compiled into the Rust binaries and
carry their own attribution duty. A hand-maintained `docs/attribution/image-notice.md`
(pinned version + URL + SPDX per tool, matching the Dockerfile ARG pins) is `COPY`'d
into both production images. This is deliberately **not** the `attribution` command
and must never be conflated with it. The dev/E2E client image is deferred (not
operator-shipped).

### D4 — DSN-free subcommands

`license` (`--full` dumps both texts) and `attribution` (`--format {text,json}`) are
synchronous print-and-exit commands on `hort-server`/`hort-worker`/`hort-cli`,
calling `hort_attribution::render_*` — no config, no DSN, no runtime, no
`AppContext` (mirroring `hort-cli completions` / `hort-server validate-config`). The
content lives once in `hort-attribution`; each binary adds only a thin clap variant.

## Consequences

- Each consumer chooses MIT or Apache-2.0; patent-conscious adopters get the §3
  grant. A downstream redistributor has a machine-checkable answer to "what's
  compiled in and under what terms" (`attribution --format json`) and a human doc
  (`THIRD-PARTY-LICENSES.md`).
- A dependency change that alters the graph must regenerate + commit the attribution
  in the same PR, or the CI gate fails (same discipline as the metrics/auth catalogs;
  documented in `CONTRIBUTING.md`).
- Attribution completeness rides on `about.toml` `accepted` == `deny.toml` allow: any
  shipped license is in the allowlist (else `cargo deny` fails) and therefore
  attributable — the two gates together close the loop.
- `hort-cli` stays isolated (`hort-attribution` is a zero-dep leaf); the subcommands
  add no DB/runtime surface.

## Alternatives considered

- **Put the shared impl in `hort-domain`/`hort-app`.** Rejected: drags a `hort-*` lib
  into `hort-cli`, breaking its pure-HTTP-client isolation (a load-bearing dep-graph
  invariant). The zero-dep leaf crate is the only shape that preserves it.
- **Hand-maintain the crate attribution list.** Rejected: the graph changes on every
  `cargo update`; a manual list is stale-by-design and is the legally-relevant
  surface. Generated + CI-verified is the only safe form.
- **Conflate compiled-in crates and image-bundled tools into one document/command.**
  Rejected: they are distinct legal surfaces (linked-in vs invoked-as-external-tool)
  with different provenance and update cadence.
- **Emit a full SBOM instead.** Out of scope: `release.yml` already produces a
  `cargo-cyclonedx` SBOM; `attribution` is human/JSON license attribution, a
  different artifact.
- **A single license (relicense to Apache-2.0 only).** Rejected: MIT is retained as
  one option so GPLv2-consuming downstreams are unaffected.

## References

- `crates/hort-attribution/src/lib.rs`; `about.toml`; `THIRD-PARTY-LICENSES.{md,json}`;
  `scripts/{regenerate,check}-attribution.sh`.
- `crates/hort-{server,worker,cli}` — the `license`/`attribution` subcommand handlers.
- `docs/attribution/image-notice.md`; `docker/Dockerfile.{hort-server,worker}`.
- `docs/architecture/how-to/third-party-attribution.md` — the operator/contributor how-to.
- [0009](0009-least-privilege-runtime-migrate-subcommand.md),
  [0017](0017-metrics-catalog-canonical.md),
  [0018](0018-auth-catalog-canonical.md).
