# Operate scanning and artifact governance

Apply scan and quarantine policies deliberately, and verify their effect with actual artifact clients before relying on them in production.

## Prepare a policy change

1. Decide whether the `ScanPolicy` applies globally or to specific repositories.
2. Confirm the worker can reach the scanners and required external services; native Linux installations require separate scanner binaries.
3. Review who can create exclusions, approve exceptions, or change policy scope.
4. Run the configuration validator against the complete set of YAML resources:

   ```bash
   HORT_CONFIG_DIR="$PWD/config" hort-server validate-config --strict
   ```

5. Deploy the reviewed files and restart `hort-server` so they are applied at startup.

Offline validation checks configuration rules but cannot confirm that scanning tools, databases, queues or external feeds work in the deployment.

## Verify quarantine and scanning

1. Use a dedicated test repository and a known test artifact.
2. Perform the intended push or pull with a real client.
3. Inspect the artifact's quarantine/scan state and worker logs.
4. Verify that access is restricted while required checks are pending and that the final client-visible result matches the policy.
5. Check failure cases: unavailable scanner, timeout, policy denial, and retry behavior.

Depending on the OCI workflow and scan state, a client may receive `503` and `Retry-After` during quarantine. Treat that as a possible policy-controlled response, not automatically as an infrastructure outage. Prefer immutable digests when validating image identity.

## Handle findings and exceptions

Keep **waivers, blocks and exclusions** distinct in review procedures. Grant curator privileges only to authorized operators and record the reason, scope, approver, and expiry/review date of an exception in your operational process. Before removing an exclusion, assess the effect on artifacts previously evaluated under it.

Retention is a separate concern: define and verify deletion/retention rules based on storage and compliance needs instead of assuming scanning controls lifecycle management.

**Related guides:** [Server & workers](workers.md) · [Monitoring & troubleshooting](monitoring.md) · [Declarative configuration](../configuration/declarative.md).
