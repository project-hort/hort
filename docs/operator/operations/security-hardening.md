# Security hardening checklist

Use this checklist before exposing hort to users or CI workloads, and revisit it after significant deployment changes. It is a practical operator review, not a substitute for an organization-specific security assessment.

## Network and TLS

- [ ] Serve registry and API endpoints through HTTPS with a valid certificate.
- [ ] Restrict the PostgreSQL, Redis and object-storage networks to the processes that need them.
- [ ] Restrict outbound network traffic to intended registries, identity providers and other approved services.
- [ ] Consider an explicit `HORT_UPSTREAM_ALLOWLIST_HOSTS` of sanctioned upstream hostnames on production proxies. The default (unset) does not enforce a host list, and the allowlist is checked on **created/updated mappings at apply time**, not continuously against every existing mapping; audit current mappings before tightening the list.
- [ ] Install necessary enterprise CA roots instead of disabling TLS verification; see [Trust custom CAs](../installation/custom-ca.md).
- [ ] Keep the **server** admin metrics listener private and require a token with a global `read_metrics` grant. If **worker** metrics are enabled, restrict access via NetworkPolicy and its explicit scrape allowlist: the worker listener has no equivalent per-request token guard. See [Monitoring & troubleshooting](monitoring.md).

## Identity and authorization

- [ ] Configure a group-capable OIDC provider for human operators.
- [ ] Limit administrator membership and verify that group claims are actually emitted.
- [ ] Bootstrap the first administrator only with the restricted recovery procedure; see [Bootstrap administrator access](../configuration/admin-bootstrap.md).
- [ ] Give CI workloads explicit, narrowly scoped `PermissionGrant` resources; avoid broad grants.
- [ ] Verify both an authorized and a forbidden client operation before onboarding users.

## Secrets and configuration

- [ ] Keep credentials out of Git-managed YAML and published Helm values.
- [ ] Supply private-upstream credentials with `secretRef` and restricted mounts; see [Supply upstream credentials](../configuration/upstream-secrets.md).
- [ ] Run `hort-server validate-config --strict` against the **complete** configuration directory before deploying changes.
- [ ] Review and approve configuration changes; restart the server to apply them and verify the result.
- [ ] Restrict access to database credentials, admin tokens and worker scanner caches.

## Storage, workers and recovery

- [ ] Give runtime and migration database accounts only their required permissions; see [Prepare PostgreSQL](../installation/postgresql.md).
- [ ] Set independent CPU/memory requests and limits for API and scan workers, based on observed workloads; see [Server & workers](workers.md).
- [ ] Verify scanning, quarantine and approval policies with a representative artifact; see [Scanning & governance](scanning-governance.md).
- [ ] Monitor failed jobs, upstream errors and storage capacity. Protect metrics credentials.
- [ ] Maintain tested backups of the artifact store **and** PostgreSQL, and an upgrade/rollback procedure; see [Configure artifact storage](../installation/storage.md) and [Upgrade hort](../installation/upgrade.md).

## Verify after deployment

Perform a real client operation, including a denied access attempt, and inspect both server and worker logs for errors. If the deployment uses Kubernetes, review rendered Helm manifests and workload security settings before rollout. Do not treat a successful health probe as proof that TLS, authorization, storage recovery and policy enforcement all work.
