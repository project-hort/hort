# Hort

**Hort** is a secure, self-hostable, multi-format artifact repository and
supply-chain registry — one server that proxies, stores, scans, and governs
packages across your package ecosystems, so you don't have to trust an
upstream registry with your build pipeline's integrity.

If you're evaluating it alongside Artifactory, Nexus, or Harbor, here's what's
structurally different, not just configurable:

- **Enforced content-addressed storage.** Every artifact's identity is the
  SHA-256 of its raw bytes, computed while streaming. Storage keys are never
  caller-supplied — there is no code path that lets a client dictate where its
  own upload lands.
- **Mandatory upstream verification.** Every pull-through fetch verifies a
  checksum against the upstream registry — the protocol-native digest for
  OCI, parsed upstream metadata for Cargo / npm / PyPI / Maven. A format that
  cannot verify its upstream cannot proxy through Hort at all; there is no
  opt-out.
- **Quarantine + fail-closed scan gate.** Pulled and pushed artifacts can be
  held until a vulnerability scan, upstream verification, and policy
  evaluation all clear. The release predicate fails closed — an
  indeterminate scan blocks release, it never defaults to "let it through."
- **Event-sourced, tamper-evident audit trail.** Every artifact state
  transition (ingest, quarantine, scan result, release, promotion) is an
  immutable domain event in a per-stream cryptographic chain — not a mutable
  row a privileged operator could quietly edit.
- **Self-hostable, sovereign by design.** Run the whole stack — server,
  worker, and its own cold-start dependencies — without a single image
  pulled from a third-party registry. See the
  [self-contained install path](docs/architecture/how-to/deploy/self-contained-registry-install.md).
- **Open source.** MIT or Apache-2.0, your choice.

The name captures the first four of these as a mnemonic:

**HORT** = **H**ashed · **O**rigin · **R**epository · **T**rail

## Status

Hort is pre-1.0 and under active development, approaching a v1.0 release.
The shipped format surface (OCI, npm, PyPI, Cargo, Maven/Gradle — see
[Supported formats](#supported-formats)) is exercised by an end-to-end test
suite against real client tooling on every release, but the project has not
yet had a stable major version or a wide production install base. Evaluate
accordingly; see [Releases](https://github.com/project-hort/hort/releases)
for what's tagged today.

[![CI](https://img.shields.io/github/actions/workflow/status/project-hort/hort/ci.yml?branch=develop&label=CI)](https://github.com/project-hort/hort/actions/workflows/ci.yml)
[![E2E](https://img.shields.io/github/actions/workflow/status/project-hort/hort/e2e.yml?branch=develop&label=E2E)](https://github.com/project-hort/hort/actions/workflows/e2e.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Latest release](https://img.shields.io/github/v/release/project-hort/hort?include_prereleases&sort=semver)](https://github.com/project-hort/hort/releases)

## Install the CLI

```sh
# Linux / macOS
curl -fsSL https://hort.rs/install-cli.sh | sh

# Windows (PowerShell)
irm https://hort.rs/install-cli.ps1 | iex
```

The installer is **fail-closed** — it verifies each download's SHA-256 and keyless cosign
signature before installing (bootstrapping a pinned cosign if you don't have one), with no
option to skip verification. See [docs/architecture/how-to/install-cli.md](docs/architecture/how-to/install-cli.md).

## Quickstart

### Option A — self-contained Helm chart (turnkey)

The fastest way to a fully sovereign install — the chart's `registry.hort.rs`
flavor pulls every image (server, worker, and cold-start dependencies) from
Hort's own registry, never `ghcr.io` or Docker Hub directly:

```bash
helm install hort oci://registry.hort.rs/hort-charts/hort-server \
  -f my-values.yaml
```

See [self-contained-registry-install.md](docs/architecture/how-to/deploy/self-contained-registry-install.md)
for the two chart flavors and what resolves from where, and
[install.md](docs/architecture/how-to/deploy/install.md) for cluster
prerequisites, the Postgres role setup, and OIDC configuration.

### Option B — run the binary directly

PostgreSQL is an external dependency (filesystem storage is the default; S3 is
optional). Apply the schema first with the least-privilege `migrate`
subcommand — the runtime itself never runs DDL:

```bash
docker run --rm \
  -e DATABASE_URL="postgresql://hort:hort@db:5432/hort" \
  ghcr.io/project-hort/hort-server:latest migrate
```

Then run the server with the `serve` subcommand (it is also the default if no
subcommand is given; shown explicitly here, matching the Helm/CI invocation):

```bash
docker run --rm -p 8080:8080 \
  -e DATABASE_URL="postgresql://hort:hort@db:5432/hort" \
  ghcr.io/project-hort/hort-server:latest serve
```

Talk to it with the `hort-cli` client (a pure HTTP client — no database access):

```bash
hort-cli auth login
hort-cli whoami
```

Point a native client at a repository — for example PyPI:

```bash
pip install --index-url http://localhost:8080/<repo>/simple/ <package>
```

## Supported formats

| Ecosystem | Client |
|---|---|
| OCI / Docker | `docker`, `skopeo`, `cosign` |
| npm | `npm`, `yarn`, `pnpm` |
| PyPI | `pip`, `uv` |
| Cargo | `cargo` |
| Maven / Gradle | `mvn`, `gradle` |

**Roadmap** (not yet shipped): additional ecosystems (Helm, RPM/YUM,
Debian/APT, …), and loading format handlers as sandboxed, deploy-time WASM
modules rather than today's compiled-in per-format adapters. See
`docs/architecture/` for the design.

## Architecture

Hort is layered hexagonally (onion):

```
domain (pure Rust, zero I/O)
  → application (use cases, orchestration)
    → outbound port traits
      → adapters (PostgreSQL, object storage, scanners)
inbound HTTP adapters (one crate per format) → composition root
```

- **Event-sourced lifecycle.** Artifact state transitions produce immutable
  domain events (`ArtifactIngested`, `ArtifactQuarantined`, `ScanCompleted`,
  `ArtifactReleased`, `ArtifactPromoted`, …). Repository config, users, and
  RBAC stay CRUD.
- **Enforced CAS.** `StoragePort::put(stream) → ContentHash` — streaming
  SHA-256, no buffering, no caller-supplied keys.
- **Quarantine + scanning.** Pulled and pushed artifacts can be held in
  quarantine until a fail-closed release predicate (vulnerability scan,
  upstream verification, policy) is satisfied.
- **Format modularization (roadmap).** The architecture is designed to load
  formats as sandboxed, deploy-time WASM modules from `$WASM_PLUGIN_DIR`, each
  declaring its capability groups in a manifest. Today's format handlers are
  compiled-in per-format adapters.

## API

- **First-party REST surface:** `/api/v1` (auth, admin, repository management,
  discovery).
- **Protocol surfaces** are served at each ecosystem's mandated path — notably
  the OCI Distribution Spec `/v2/...`, which is orthogonal to the first-party
  `/api/v1` and is not a Hort API version.

## Documentation

- **Operators** — [docs/architecture/](docs/architecture/), the Diátaxis
  documentation set (`explanation/`, `how-to/`, `reference/`, `tutorial/`),
  covering deployment, gitops configuration, auth, and scanning.
- **Contributors** — every workspace crate under `crates/` has its own
  `README.md` describing its layer, ports, and governing rules; start at
  [`docs/architecture/explanation/layers.md`](docs/architecture/explanation/layers.md)
  for the overall shape, and [CONTRIBUTING.md](CONTRIBUTING.md) for the
  workflow.
- `docs/adr/` — Architecture Decision Records; [ADR 0000](docs/adr/0000-historical-decisions-index.md)
  indexes the historical decision trail.
- [`docs/auth-catalog.md`](docs/auth-catalog.md),
  [`docs/metrics-catalog.md`](docs/metrics-catalog.md) — the authoritative
  auth and metrics catalogs.

## Building from source

Rust 1.94+ workspace:

```bash
cargo build --workspace
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development workflow,
including the regression-test contract and the security-issue reporting
process.

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. This means you may select the license of your choice when
using this software.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.

---

Built primarily with [Claude Code](https://claude.com/claude-code).
