# host-tests — host-side orchestration smokes

These scripts are **NOT** part of the containerized `scripts/native-tests/run.sh`
harness. They run directly on the host because each one does at least one of the
following, which is impossible from inside a client container:

- Restarts the compose stack with a generated config overlay (remounts
  `HORT_CONFIG_DIR` onto a transient directory, then restores the canonical tree
  on exit).
- Mints a server-signed service token via
  `docker compose exec hort-server hort-server admin issue-svc-token`.
- Owns the entire `hort` compose project — brings the stack up with an extra
  overlay (e.g. the federation OIDC issuer) and runs `compose down -v` before and
  after the test.

## Scripts

| Script | Purpose |
|---|---|
| `test-gitops-policies.sh` | E2E smoke for the gitops-managed policy and RBAC management plane — stages a transient config dir containing one of each YAML kind (Role, PermissionGrant, CurationRule, ScanPolicy, Exclusion, GroupMapping) and asserts create/edit/idempotent-reapply/removal lifecycle events and projections. |
| `test-vulnerability-scan.sh` | E2E smoke for the vulnerability-scanning producer pipeline — ingests a known-CVE npm artifact, asserts the worker quarantines it, adds an Exclusion, and asserts the artifact is released; requires the `worker` compose profile. |
| `test-rescanning.sh` | E2E smoke for the rescanning and manual-rescan path — verifies Helm CronJob template rendering, then exercises forced eligibility (psql backdate), cron-rescan-tick invocation via `hort-cli admin task invoke`, and manual `hort-cli admin rescan`. |
| `test-task-framework.sh` | E2E smoke for the admin-task framework HTTP surface — exercises token bootstrap via `hort-server admin issue-svc-token`, POST/GET task enqueue, `/metrics` emission, and the TaskInvoked audit event. |
| `test-notifications.sh` | E2E smoke for the event-notification substrate — asserts SSRF and plaintext-webhook blocks, the `hort_unsafe_config_active` gauge, the pull-resync events surface, and the subscription CRUD surface. Opt-in: set `HORT_RUN_INIT35_NOTIFICATIONS_E2E=1`. |
| `test-notifications-rbac.sh` | Claim-based-RBAC event-delivery regression smoke — POSITIVE: OIDC group claims flow to subscription scope; NEGATIVE: PAT subscriptions carry no claims and deliver no events. Opt-in: set `HORT_E2E_NOTIFICATIONS=1`. |
| `test-gitops-machine-identity.sh` | Federation E2E for `POST /api/v1/auth/exchange` — brings up base + `docker-compose.federation.yml` (a compose-network nginx OIDC issuer), exchanges a federated JWT for a hort token, and asserts the machine-identity path. DESTRUCTIVE: owns the compose project (`down -v` before/after). |

## Running

Each script manages its own stack lifecycle (bring-up, config overlay, teardown).
Run them individually on the host:

```bash
bash scripts/host-tests/test-task-framework.sh
bash scripts/host-tests/test-vulnerability-scan.sh
# etc.
```

Or use the host runner to run all of them in sequence:

```bash
bash scripts/host-tests/run.sh
bash scripts/host-tests/run.sh --list   # list scripts without running
```

## Prerequisites

- Docker Compose stack at `deploy/compose/docker-compose.yml` (some scripts bring
  it up themselves; the scanning smoke uses `--profile worker`).
- `HORT_TOKEN_ALLOW_ADMIN=true` in the `hort-server` container environment for
  scripts that mint service tokens (`test-task-framework.sh`,
  `test-notifications.sh`, `test-rescanning.sh`).
- `HORT_RUN_INIT35_NOTIFICATIONS_E2E=1` to opt in to `test-notifications.sh`.
- `HORT_E2E_NOTIFICATIONS=1` to opt in to `test-notifications-rbac.sh`.
- `HORT_TEST_DEBUG=1` toggles `set -x` in scripts that support it.

Scripts that cannot reach the compose stack exit **2** (environment unmet, not a
test failure).

## See also

`scripts/native-tests/README.md` — the containerized client/db/cli scenarios
(PyPI, npm, Cargo, OCI round-trip, OCI mirror pull-through, gitops,
patch-candidate, pull-dedup). `scripts/k8s-tests/README.md` — the kind-cluster
smokes.
