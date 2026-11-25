# 478 — the deployment migration

**Issue:** #457 · **Branch:** `agent/457-transport-evidence` · Unit 7 of 7.
**Design:** `docs/plans/457-transport-evidence.md` §2.7, §4.3.1, §5.
**Depends on 471–474.** The §3 decision is answered: a declared hop is
acceptable, so the chart declares one rather than moving to HTTPS.
**Read first:** `deploy/helm/hort-server/templates/cronjob-*.yaml` (all
eleven), `deploy/helm/hort-server/values.yaml:66-98,1464-1483`,
`deploy/helm/hort-server/templates/deployment.yaml:103-121`,
`scripts/k8s-tests/test-k8s-rotation.sh:490-560`,
`deploy/ansible/roles/hort*/templates/hort-server.env.j2`.

## The defect

**Eleven chart CronJob templates** invoke `hort-cli admin task invoke` against
`http://<Service>:<httpPort>` with `HORT_TOKEN` read from the `…-svc-token`
Secret — e.g. `cronjob-cron-rescan-tick.yaml:73-79`, and the same URL/token
pair in the other ten. Their TCP peer is a sibling pod, the chart's default
`trustedProxyCidrs` is empty (`values.yaml:85-98`), and the main listener is
`0.0.0.0:8080` (`values.yaml:66-77`). So after units 471–472 every one of them
presents a credential with `transport == Unknown` and is refused.

The existing opt-out does not rescue them: `HORT_BEARER_ALLOW_OVER_HTTP=true`
together with an `https://` `publicBaseUrl` is a **boot hard-fail**
(`config.rs:2614-2629`), which is the normal shape of a deployment that has an
ingress. This is the chart's own documented admin-task installation
(`values.yaml:1464-1483`), so it is a production break, not a harness one.

`scripts/k8s-tests/test-k8s-rotation.sh:498-506,549-557` already opts into
plaintext explicitly and stays a declared test posture.

## What to build

The eleven templates keep their Service URL; the chart declares the in-cluster
path as a **waived scope** (`HORT_TLS_NOT_REQUIRED_FROM`, design §4.3.1):

- a `values.yaml` key for it, **empty by default** so an operator who renders
  the chart without admin tasks declares nothing, rendered into the server
  Deployment's env beside `HORT_TRUSTED_PROXY_CIDRS`
  (`templates/deployment.yaml:103-121`);
- scoped as narrowly as the cluster **can express**, which is less than it
  first appears: on the ordinary source-preserving ClusterIP path the TCP peer
  is the calling CronJob pod's own ephemeral pod IP, so there is no
  Service-scoped or namespace-scoped form to prefer — the expressible
  declaration is a pod CIDR (cluster-wide or, on a CNI that assigns per-node or
  per-namespace ranges, that subset). **The guarantee is conditional and the
  values key must say so**: kube-proxy `masqueradeAll`, a mesh sidecar that
  terminates and re-dials, and `hostNetwork` clients each change the peer the
  server observes. So the key stays **empty by default**, there is **no
  portable numeric default** to suggest, and the operator's instruction is to
  **measure the peer hort actually observes** — `hort_credential_transport_total`
  carries `entry_point` and `evidence` and **no address**, so the instrument is
  the trust layer's `debug!` line, which unit 471 extends with the raw socket
  `peer` beside the derived `client_ip`. Say that, with the log level to set. Say at the knob that the waiver admits **every pod that
  can reach the socket from inside the declared range**, so a NetworkPolicy
  restricting who may reach the Service is the remaining control, not the CIDR;
- **the ingress overlap is closed by the precedence rule, not by the CIDR**
  (design §4.3.2), and specifically by the **not-relayed** condition: an
  ingress controller pod shares the cluster pod range, and a peer-only waiver
  would have covered it even when the operator has *not* listed it as a trusted
  proxy — an external plaintext request could then have minted a token. Say at
  the knob that a declared range admits only **unrelayed** callers, that any
  ingress or proxy in that range should also be in `HORT_TRUSTED_PROXY_CIDRS`
  (which it must be anyway for client-IP attribution), and name the residual
  case the operator owns: an L7 ingress that adds no forwarding header at all,
  source-NATs into the range and is absent from the trust list — a deployment
  whose client-IP attribution is already dead. **Verify the relayed refusal in
  acceptance**, not only the trusted-proxy one;
- **do not offer "declare the hop" for a trusted internal proxy that reports
  `proto=http`**: that is `Plaintext` evidence and a scope never waives it
  (design §4.3.2). Such a topology needs a direct, unrelayed path to the
  listener or TLS on that hop — say so instead of implying a declaration
  rescues it;
- **the loopback metrics scrape** (design §2.3, §5.7): the chart binds the
  metrics listener to `127.0.0.1:9090` for a sidecar scrape whose peer is
  loopback, which no pod CIDR covers. Either the rendered waiver includes
  `127.0.0.1/32` or the listener gets TLS; whichever the chart does, the values
  key and the scrape how-to say what a loopback waiver admits (any process in
  the pod's network namespace) and list `426` as a scrape failure mode;
- the admin-task installation section (`values.yaml:1464-1483`) states that the
  key is required for the CronJobs and why, and that the alternative is an
  HTTPS endpoint with `HORT_EXTRA_CA_BUNDLE` (ADR 0010 — never an
  insecure-TLS knob);
- do **not** weaken the `https`-base boot gate (`config.rs:2614-2629`) to let
  the unscoped flag through instead.

Also:

- every one of the eleven templates is updated — enumerate them in the report,
  do not fix the one the item quotes;
- `values.yaml` documents what an operator must set, and the admin-task
  installation section is corrected;
- the Ansible env templates are reviewed against the same rule
  (`HORT_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128` means a loopback proxy: it
  keeps working **only** if that proxy overwrites a forwarded scheme — say so
  where the template says it);
- **the kind smoke stops using the unscoped flag**:
  `scripts/k8s-tests/test-k8s-rotation.sh:549-557` sets
  `HORT_BEARER_ALLOW_OVER_HTTP` through `extraEnv`, which would let the test
  pass without ever exercising the chart's new scoped value. Remove it and set
  the new value instead, so the smoke proves the path operators will use;
- `bash scripts/run-shell-guards.sh` and the Helm template rendering stay
  green (`helm` is not available in the sandbox — if `scripts/test-helm-templates.sh`
  exits 2 for that reason, report it as not-run, never as passed).

## Acceptance

- All eleven CronJob templates are updated and named in the report.
- A rendered chart with admin tasks enabled and the new key set produces a
  server Deployment whose env waives the in-cluster path, and CronJobs that
  can authenticate — demonstrated by the rendering plus the reasoning, or by
  the k8s smoke where it can run.
- A rendered chart with the key **unset** still renders, and the documentation
  says what happens to the CronJobs then (they are refused — that is the
  loudness, not a regression).
- A peer in the declared range that is **also** a trusted proxy is refused —
  the ingress case, asserted at whatever level the unit can reach it (the
  predicate's unit tests at minimum).
- The kind smoke passes **without** `HORT_BEARER_ALLOW_OVER_HTTP` anywhere in
  its values.
- No change weakens an existing boot gate, and no `*_INSECURE_TLS`-shaped knob
  appears anywhere (ADR 0010).
- The Ansible templates' comments state the overwrite obligation.
- Gate: `cargo test --workspace` unchanged (no Rust change expected), shell
  guards run, Helm rendering reported honestly.
