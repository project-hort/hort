# Contributing to Hort

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/hort.git`
3. Create a feature branch: `git checkout -b feat/your-change` (`feat/`,
   `fix/`, `chore/`, `docs/`)
4. Make your changes
5. Run checks: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --lib && cargo audit --deny warnings`
6. Commit and push to your fork
7. Open a Pull Request against `main`

## Development Setup

### Prerequisites

- Rust 1.94+ (MSRV — see `.clippy.toml`)
- PostgreSQL 16
- Docker & Docker Compose (for integration / E2E tests)

### Running Locally

```bash
# Start dependencies (Postgres)
docker compose -f deploy/compose/docker-compose.yml up -d postgres

# Apply the schema (separate least-privilege subcommand; the runtime never runs DDL)
cargo run -p hort-server -- migrate

# Run the server
cargo run -p hort-server -- serve

# Run unit tests
cargo test --workspace --lib
```

The full local E2E stack (Postgres + Keycloak + hort-server) is brought up by
`./scripts/native-tests/run.sh --hort=compose` against `deploy/compose/`. See `TESTING.md`.

## What to Contribute

- **Bug reports** — File an issue with steps to reproduce
- **Bug fixes** — Open a PR referencing the issue
- **New package format handlers** — Follow
  [`docs/architecture/how-to/add-a-format-handler.md`](docs/architecture/how-to/add-a-format-handler.md)
- **Documentation improvements** — The Diátaxis docs live in `docs/architecture/`
- **Feature requests** — Open an issue or discussion on
  [the repository](https://github.com/project-hort/hort)

## Guidelines

- Keep PRs focused on a single change
- Follow existing code style (`cargo fmt` enforces this)
- Add tests for new functionality
- Update documentation if your change affects user-facing behavior

Architecture-affecting work should go through the `hort-architect` skill
(`.claude/commands/hort-architect.md`) — it encodes the domain model, port
contracts, and the anti-patterns checklist reviewers apply.

## Regression-test contract for bug fixes

Every PR that fixes a bug must land with a regression test that fails on
`main` and passes on the PR. This is enforced by reviewer policy:
`fix/*` PRs are not approved without a regression test.

The test can live wherever fits the bug:

- **Unit test** in the same crate as the fixed code, when the bug is
  in pure logic.
- **Integration test** (`crates/*/tests/`) when the bug requires a real
  database, storage backend, or HTTP client.
- **End-to-end test** under `scripts/native-tests/` (driven by
  `./scripts/native-tests/run.sh --hort=compose`), when the bug surfaces only when the deployed
  system is exercised through its native client (`npm`, `pip`, `cargo`,
  `docker`/`skopeo`).

For PRs that aren't bug fixes (`feat/`, `chore/`, `docs/`, `ci/`,
`refactor/`), no regression test is required — the reviewer confirms
this in the MR review.

## Reporting Security Issues

Please do **not** open a public issue for security vulnerabilities — see
[`SECURITY.md`](SECURITY.md) for how to report privately.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).
