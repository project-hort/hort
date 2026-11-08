# hort

**Artifact repositories with integrity built in.**

hort is a multi-format artifact repository for consuming, storing, and publishing
software artifacts. It combines verified upstreams, content-addressed storage,
policy-driven scanning, and an auditable, event-sourced artifact lifecycle.

[Project website](https://project-hort.de/) · [Operator documentation](https://project-hort.de/docs/) · [Developer documentation](https://hort.rs/) · [Releases](https://github.com/project-hort/hort/releases)

[![CI](https://img.shields.io/github/actions/workflow/status/project-hort/hort/ci.yml?branch=develop&label=CI)](https://github.com/project-hort/hort/actions/workflows/ci.yml)
[![E2E](https://img.shields.io/github/actions/workflow/status/project-hort/hort/e2e.yml?branch=develop&label=E2E)](https://github.com/project-hort/hort/actions/workflows/e2e.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=project-hort_hort&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=project-hort_hort)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=project-hort_hort&metric=coverage)](https://sonarcloud.io/summary/new_code?id=project-hort_hort)
[![Security](https://sonarcloud.io/api/project_badges/measure?project=project-hort_hort&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=project-hort_hort)
[![Reliability](https://sonarcloud.io/api/project_badges/measure?project=project-hort_hort&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=project-hort_hort)
[![Maintainability](https://sonarcloud.io/api/project_badges/measure?project=project-hort_hort&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=project-hort_hort)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Latest release](https://img.shields.io/github/v/release/project-hort/hort?include_prereleases&sort=semver)](https://github.com/project-hort/hort/releases)

## Why hort?

- **Verified upstreams.** Pull-through requests verify the artifact against
  upstream integrity metadata specific to each supported ecosystem.
- **Content-addressed storage.** Artifact bytes are stored using their SHA-256
  content hash, backed by a filesystem or S3-compatible object storage.
- **Scanning and governance.** Quarantine and policy evaluation control when
  artifacts become available; indeterminate scan results do not silently pass.
- **Tamper-evident event store.** Artifact lifecycle transitions are recorded as
  immutable domain events in per-stream cryptographic chains, making changes
  to the event history detectable. Identity and permission-grant *decisions*
  are recorded the same way; the configuration they produce is held as
  ordinary state.
- **Independent workers.** Scanning and background tasks run in separate
  `hort-worker` processes, allowing independent CPU and memory allocation.
- **Configuration as code.** Define repositories, upstreams, policies, and
  access rules in files; validate using `hort-server validate-config --strict`.
  Configuration is applied at server startup, not continuously reconciled.
- **Operational observability.** Health endpoints and metrics provide inputs
  for monitoring, diagnostics, automation, and AI-assisted operations.

## Supported ecosystems

| Ecosystem | Common clients |
| --- | --- |
| OCI / Docker | `docker`, `skopeo`, `cosign` |
| npm | `npm`, `yarn`, `pnpm` |
| PyPI | `pip`, `uv` |
| Cargo | `cargo` |
| Maven / Gradle | `mvn`, `gradle` |

Capabilities vary by ecosystem; consult the
[operator documentation](https://project-hort.de/docs/) for configuration
and supported workflows.

## Getting started

hort runs on **native Linux** (separate server and worker services) or
**Kubernetes with Helm**. Both deployment paths require PostgreSQL and
configured artifact storage. See the
[operator quickstart and installation guides](https://project-hort.de/docs/)
for prerequisites, repository setup, and your first artifact workflow.

## Development and tools

[hort.rs](https://hort.rs/) covers the Rust crates, architecture, extension
points, development workflow, and CLI downloads.

`hort-cli` is an operator tool for managing hort through its API; it is not
required for normal artifact clients such as Docker, npm, or pip.

For contributions, see [CONTRIBUTING.md](CONTRIBUTING.md). The
[architecture decisions](docs/adr/0000-historical-decisions-index.md) include
historical designs and proposals, not only shipped capabilities.

## Project status

hort is under active development and has not yet reached version 1.0.
Consult the [releases](https://github.com/project-hort/hort/releases)
and their notes before installing or upgrading.

## License

Dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
