# Test changes to hort

Choose the smallest test level that can establish your change's behavior, then run broader checks before proposing a merge. Test requirements may change: consult the current repository CI and [TESTING.md](../../../TESTING.md).

## Check formatting and lint

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
```

These checks don't require a running database. For focused changes, a single crate test can be more efficient:

```sh
cargo test -p hort-domain --lib
```

## Database-backed integration tests

`cargo test --workspace` includes tests that require PostgreSQL. The repository documents a Compose database fixture and a `DATABASE_URL` for running them. Consult [TESTING.md](../../../TESTING.md) before running; use an **isolated test database**, never a production database.

## End-to-end tests

The native-client harness lives under `scripts/native-tests/` and exercises registry behavior with real package clients against a Compose deployment.

```sh
./scripts/native-tests/run.sh --hort=compose
```

For the second CI lane, use the native-tokens overlay described in [TESTING.md](../../../TESTING.md). These tests require Docker/Compose and additional resources; they are not equivalent to a native Linux systemd installation or a full Helm deployment test.

## Review before sending a pull request

- Confirm the changed behavior has an appropriate test.
- Run formatting, lint and relevant test suites.
- Update user-facing docs when behavior changes, keeping operator instructions on [project-hort.de](https://project-hort.de/docs/index.html).
- Avoid committing test credentials, generated data or local secrets.

See [CONTRIBUTING.md](../../../CONTRIBUTING.md) for review and contribution conventions.
