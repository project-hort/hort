# 041 — Operator documentation sweep (v1.0 prep 1/3)

**Issue:** #68
**Read first:** the operator-doc inventory below; `deploy/helm/hort-server/values.yaml` (38 keys),
`crates/hort-server/src/config.rs` (the ~180 `HORT_*` env vars — source of truth),
`crates/hort-config/**` (gitops kinds/fields), `crates/hort-cli/**` (CLI surface),
ADR 0051 + `docs/adr/` for the as-built.

## Goal

Sweep the **operator-facing** docs for consistency + up-to-dateness against shipped v0.9.12
behavior, before v1.0. Fix drift; where a doc contradicts the as-built and the fix isn't a simple
doc edit, raise a follow-up issue (docs follow the spec/ADR authority hierarchy — don't invent
behavior to match a stale doc).

## Inventory (the operator surface — review every file)

- `docs/operator/`: `idp-setup.md`, `upstream-trust-model.md`
- `docs/architecture/how-to/deploy/`: `install.md`, `values-reference.md`,
  `self-contained-registry-install.md`, `security-hardening-checklist.md`, `postgres-roles.md`,
  `extra-ca-bundle.md`, `local-bringup.md`, `control-plane-tiers.md`, `admin-identity-and-dex.md`,
  `enable-admin-task-cronjobs.md`, `examples-overlays.md`
- `docs/architecture/how-to/operate/`: `claim-based-rbac.md`, `oci-imagepull-secret-token.md`,
  `public-supply-chain-deployment.md`
- `docs/architecture/how-to/` (operator how-tos): `install-cli.md`, `wire-secrets.md`,
  `federate-ci-oidc.md`, `federate-k8s-workload-identity.md`, `oci-pull-through.md`,
  `npm-pull-through.md`, `pypi-pull-through.md`, `enable-provenance-verification.md`,
  `quarantine-patch-release.md`, `rotating-service-account-tokens.md`,
  `recover-stranded-artifacts.md`, `release-verification.md`,
  `using-hort-cli-with-admin-ops.md`, `declare-gitops-config.md`, `http-transport-timeouts.md`,
  `third-party-attribution.md`, `curator-workflow.md`, `cli-completions.md`
- `docs/architecture/reference/`: `helm-chart.md`, `server-and-worker-configuration.md`

## Drift dimensions (check each doc against)

1. **`HORT_*` env vars** — no doc references a removed/renamed var; documented defaults match
   `config.rs`. (180 in code; don't enumerate all, but every var a doc *mentions* must be current.)
2. **Helm values** — keys/defaults in `values-reference.md` / `helm-chart.md` match
   `deploy/helm/hort-server/values.yaml` (incl. the #60 `global.imageRegistry` block).
3. **Gitops kinds/fields** — `apiVersion` shown as `project-hort.de/v1beta1` (note: #67 will add
   `v1` — coordinate; for now v1beta1 is correct); kinds + fields match `hort-config`.
4. **CLI** — commands/flags/subcommands match `hort-cli`; no removed flags.
5. **Version/tag/URL drift** — no stale `0.9.x`/`v0.9`/`:1.0` version pins, dead image tags, or
   dead cross-links (several deploy how-tos carry version refs — verify each).
6. **#60 self-contained registry** — `self-contained-registry-install.md` +
   `examples-overlays.md` consistent with ADR 0051 (the `registry.hort.rs` chart flavor, hort-base,
   the cold-start chain) and with #71's `hort-charts` once it lands.
7. **Cross-links + Diátaxis placement** — internal links resolve; each doc reachable from the
   `docs/architecture/README.md` nav.

## Acceptance

- Every inventoried doc reviewed; drift fixed or a follow-up issue filed.
- No stale env vars / values / versions / dead links in operator docs.
- Consistent with the as-built (config.rs, values.yaml, hort-config, hort-cli, ADRs).
- Scoped to operator docs only (developer docs = #69, root README = #70).

Likely batched by group (deploy / operate / reference / operator+how-tos) in sub-commits; one MR.

### Starter prompt

```
/hort-architect

Implement backlog item 041 (issue #68) on branch agent/68-operator-docs-sweep. Docs-only sweep
of the operator surface (inventory in the backlog item). For each doc, check against the as-built:
HORT_* env vars (config.rs), Helm values (values.yaml, incl. global.imageRegistry), gitops
kinds/fields (hort-config, apiVersion project-hort.de/v1beta1), CLI (hort-cli), and version/link
drift. Fix drift; file a follow-up issue for any as-built-vs-doc contradiction that isn't a simple
edit. Batch by group in sub-commits. Run cargo test --workspace + fmt + clippy (docs-only, but run
the gate — any doc-embedded structural guards must pass). Report per the handover protocol.
```
