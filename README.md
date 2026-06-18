# Hort

**Hort** is a universal, multi-protocol artifact repository and supply-chain
platform — one server that proxies, stores, scans, and governs packages across
every major package ecosystem, built on a hexagonal, event-sourced architecture.

> Built mainly with **Claude Opus 4.7 (1M context)**.

The name is the platform's four load-bearing guarantees:

**HORT** = **H**ashed · **O**rigin · **R**epository · **T**rail

- **Hashed** — enforced content-addressed storage. Content identity is the
  SHA-256 of the raw bytes, computed while streaming; callers never supply
  storage keys.
- **Origin** — mandatory upstream verification. Every pull-through fetch
  verifies a checksum (the protocol-native digest for OCI; parsed upstream
  metadata for Cargo / PyPI / npm). A format that cannot verify cannot proxy.
- **Repository** — the multi-protocol artifact surface: OCI, npm, PyPI, and
  Cargo, each served through a dedicated inbound adapter behind one set of
  domain ports.
- **Trail** — the event-sourced artifact lifecycle and a tamper-evident,
  per-stream cryptographic event chain. Every state transition is an immutable
  event; the chain is the audit trail.

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

## Architecture

Hort is layered hexagonally (onion):

```
domain (pure Rust, zero I/O)
  → application (use cases, orchestration)
    → outbound port traits
      → adapters (PostgreSQL, object storage, scanners)
inbound HTTP adapters (one crate per protocol) → composition root
```

- **Event-sourced lifecycle.** Artifact state transitions produce immutable
  domain events (`ArtifactIngested`, `ArtifactQuarantined`, `ScanCompleted`,
  `ArtifactReleased`, `ArtifactPromoted`, …). Repository config, users, and
  RBAC stay CRUD.
- **Enforced CAS.** `StoragePort::put(stream) → ContentHash` — streaming
  SHA-256, no buffering, no caller-supplied keys.
- **Format modularization (roadmap).** The architecture is designed to load
  formats as sandboxed, deploy-time WASM modules from `$WASM_PLUGIN_DIR`, each
  declaring its capability groups in a manifest. Today's format handlers are
  compiled-in per-protocol adapters.
- **Quarantine + scanning.** Pulled and pushed artifacts can be held in
  quarantine until a fail-closed release predicate (vulnerability scan,
  upstream verification, policy) is satisfied.

## Supported formats

| Ecosystem | Client |
|---|---|
| OCI / Docker | `docker`, `skopeo`, `cosign` |
| npm | `npm`, `yarn`, `pnpm` |
| PyPI | `pip`, `uv` |
| Cargo | `cargo` |

Additional ecosystems (Maven, Helm, RPM/YUM, Debian/APT, …) and WASM-based
format modularization are on the roadmap; see `docs/architecture/`.

## Quickstart

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

## API

- **First-party REST surface:** `/api/v1` (auth, admin, repository management,
  discovery).
- **Protocol surfaces** are served at each ecosystem's mandated path — notably
  the OCI Distribution Spec `/v2/...`, which is orthogonal to the first-party
  `/api/v1` and is not a Hort API version.

## Documentation

- `docs/architecture/` — the Diátaxis documentation set
  (`explanation/`, `how-to/`, `reference/`, `tutorial/`).
- `docs/adr/` — Architecture Decision Records; ADR `0000` indexes the
  historical decision trail.
- `docs/auth-catalog.md`, `docs/metrics-catalog.md` — the authoritative auth
  and metrics catalogs.

## Building from source

Rust 1.94+ workspace:

```bash
cargo build --workspace
cargo test --workspace
```

## License

MIT — see [`LICENSE`](LICENSE).
