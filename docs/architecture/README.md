# Architecture Documentation

How Hort is built and operated: everything here describes the architecture
as shipped in the `crates/` workspace.

Organised along [Diátaxis](https://diataxis.fr):

## Explanation — understand the design

Start here if you want to know **why** the system looks the way it does.

1. [Overview](explanation/overview.md) — goals, authority hierarchy, the shape of the system.
2. [Layering and crate map](explanation/layers.md) — where code lives and who may depend on whom.
3. [Domain model](explanation/domain-model.md) — entities, ports, actors, content hashes.
4. [Event sourcing](explanation/event-sourcing.md) — streams, events, dual-write, projections.
5. [Content-addressable storage](explanation/cas-storage.md) — streaming CAS and its invariants.
6. [Format handlers](explanation/format-handlers.md) — capability taxonomy and what's compiled-in today.
7. [Security](explanation/security.md) — trust boundaries, auth, authz, defence in depth, and what operators still own.
8. [The prefetch pipeline](explanation/prefetch-pipeline.md) — triggers, the transitive cascade, dedup layers, and why warming never bypasses quarantine.
9. [Index construction](explanation/index-construction.md) — the Source → Filter → Builder spine, the no-leak filter order, and IndexMode's bounded semantics.
10. [The scanning pipeline](explanation/scanning-pipeline.md) — scanner/advisory ports, SBOM extraction, the scan-job lifecycle, and the externally-triggered rescan/advisory ticks.
11. [Event notifications](explanation/event-notifications.md) — subscriptions, webhook/NATS delivery, the privileged-category gate, and the best-effort delivery contract.

## How-to — task-oriented recipes

### Configuration and operations

- [Declare configuration via `$HORT_CONFIG_DIR` (gitops)](how-to/declare-gitops-config.md)
- [Wire secrets for `proxy.secretRef:`](how-to/wire-secrets.md)
- [Tune HTTP transport timeouts](how-to/http-transport-timeouts.md)
- [Verify a release with `cosign verify-blob`](how-to/release-verification.md)
- [Use `hort-cli` for admin operations (`--admin`, `--expires-in`)](how-to/using-hort-cli-with-admin-ops.md)
- [Install `hort-cli`](how-to/install-cli.md)
- [Shell completions for `hort-cli`](how-to/cli-completions.md)
- [Federate k8s workload identity (preferred, no PAT at rest)](how-to/federate-k8s-workload-identity.md)
- [Federate CI OIDC (GitHub Actions / GitLab) via `/auth/exchange`](how-to/federate-ci-oidc.md)
- [Rotate service-account PATs via the worker reconciler (fallback)](how-to/rotating-service-account-tokens.md)
- [Enable provenance (Sigstore/cosign) verification](how-to/enable-provenance-verification.md)
- [Quarantine patch-candidates and release](how-to/quarantine-patch-release.md)
- [Recover stranded (failed-scan) artifacts](how-to/recover-stranded-artifacts.md)
- [The curator workflow](how-to/curator-workflow.md)
- [Third-party attribution](how-to/third-party-attribution.md)

### Format-specific

- [Add a format handler](how-to/add-a-format-handler.md)
- [Configure OCI pull-through with verified upstream](how-to/oci-pull-through.md)
- [Configure npm pull-through with verified upstream](how-to/npm-pull-through.md)
- [Configure PyPI pull-through with verified upstream](how-to/pypi-pull-through.md)

### Deployment

- [Install `hort-server` on Kubernetes](how-to/deploy/install.md)
- [Install `hort-server` + `hort-worker` on a single Linux host](how-to/deploy/local-bringup.md)
- [Helm chart — values reference](how-to/deploy/values-reference.md)
- [Helm chart — edge overlays](how-to/deploy/examples-overlays.md)
- [Install fully sovereign against `registry.hort.rs`](how-to/deploy/self-contained-registry-install.md)
- [Upgrade a running deployment (and `### Migration notice` releases)](how-to/deploy/upgrade.md)
- [Provision the two Postgres roles](how-to/deploy/postgres-roles.md)
- [Trust internal or corporate CAs (`extraCaBundle`)](how-to/deploy/extra-ca-bundle.md)
- [Admin identity and the Dex bootstrap](how-to/deploy/admin-identity-and-dex.md)
- [Enable admin-task CronJobs](how-to/deploy/enable-admin-task-cronjobs.md)
- [Split the control plane onto a dedicated listener](how-to/deploy/control-plane-tiers.md)
- [Security hardening checklist](how-to/deploy/security-hardening-checklist.md)

### Operate

- [Claim-based RBAC](how-to/operate/claim-based-rbac.md)
- [Provision a Prometheus scraper ServiceAccount for `/metrics`](how-to/operate/metrics-scraper-service-account.md)
- [OCI image-pull secret / token](how-to/operate/oci-imagepull-secret-token.md)
- [Public supply-chain deployment](how-to/operate/public-supply-chain-deployment.md)

### Operator

- [IdP setup](../operator/idp-setup.md)
- [Upstream trust model](../operator/upstream-trust-model.md)

## Reference — look up exact values

Information-oriented, exhaustive, kept in lockstep with the code.

- [`hort-server` and `hort-worker` configuration](reference/server-and-worker-configuration.md)
  — every env var and CLI subcommand/flag, with defaults, required-ness, and startup interlocks.
- [The `hort-server` Helm chart](reference/helm-chart.md)
  — rendered-resource matrix, install-time schema rules, hook ordering, workload wiring, and chart-vs-binary caveats.
- [Public event taxonomy](reference/event-taxonomy.md)
  — domain events external consumers may subscribe to, with payload fields, stream, and stability contract.
- [npm format — entity reference](reference/npm-format-entities.md)
  — every npm registry entity as hort handles it: stored, derived, or discarded, and why; updated whenever an initiative changes an entity's class.

## Tutorial — learn by tracing one request

- [Follow a PyPI upload end-to-end](tutorial/first-ingest.md)

## Rendering the PlantUML diagrams

Diagrams are inline fenced code blocks tagged `plantuml`. Render them with
any PlantUML-aware viewer (IntelliJ PlantUML plugin, VS Code PlantUML
extension, `plantuml` CLI, or the [online server](https://www.plantuml.com/plantuml/)).

## Primary sources

When this documentation and the code disagree, the code wins — but the
authoritative standing decisions live in the architecture decision
records under [`docs/adr/`](../adr/). The starting point is the
[decision index and open-items register](../adr/0000-historical-decisions-index.md);
each ADR names the live mechanism (code, test, or gate) that enforces
it. Official protocol specifications outrank everything (see
[ADR 0011](../adr/0011-authority-hierarchy-and-api-versioning.md)).
