# 040 — Define the `hort-charts` gitops repository (fix chart-flavor publish 404)

**Issue:** #71
**Read first:** `deploy/ansible/files/gitops/repositories/hort-oci.yaml` (model),
`deploy/ansible/files/gitops/policies/hort-oci-scan.yaml`,
`deploy/ansible/files/gitops/auth/grants/gha-release-{write,read}-hort-oci.yaml`,
`.github/workflows/docker-publish.yml` (the `Publish Helm Chart (registry.hort.rs flavor)` job,
~lines 730-760).

## Problem

#60 wired a registry.hort.rs Helm-chart flavor publish (`helm push … oci://registry.hort.rs/hort-charts`
then `cosign sign …hort-charts/hort-server@DIGEST`), but **no `hort-charts` repository is defined
in gitops**. hort doesn't auto-create repos on push, so the blob-upload POST 404s. This is a #60
gap, distinct from #66 (the image mirrors `hort-oci`/`hort-base` now succeed).

## Fix — add 4 gitops files (config only), modeled on `hort-oci`

### 1. `deploy/ansible/files/gitops/repositories/hort-charts.yaml`
Hosted OCI repo, world-readable, push restricted to `gha-release`. Mirror `hort-oci` exactly
except name/description/path:
```yaml
apiVersion: project-hort.de/v1beta1
kind: ArtifactRepository
metadata:
  name: hort-charts
spec:
  name: "Hort first-party Helm charts"
  description: "World-readable distribution of the registry.hort.rs hort-server chart flavor (turnkey/sovereign default). Push restricted to the gha-release ServiceAccount (tagged releases only)."
  format: oci
  type: hosted
  storage:
    backend: filesystem
    path: /var/lib/hort-server/cas/hort-charts
  isPublic: true
  replicationPriority: local_only
```

### 2. `deploy/ansible/files/gitops/policies/hort-charts-scan.yaml` — **`quarantineDuration: 0` is the hard requirement**
```yaml
apiVersion: project-hort.de/v1beta1
kind: ScanPolicy
metadata:
  name: hort-charts-scan
spec:
  scope:
    repository: hort-charts
  # quarantineDuration: 0 — REQUIRED, and deliberately different from hort-oci's 1h:
  # (a) the publish job cosign-SIGNS the chart immediately after push
  #     (docker-publish.yml ~line 755, `cosign sign …@DIGEST`), which resolves the
  #     just-pushed manifest back — a quarantine 503 there would fail the publish
  #     (hort-oci gets away with 1h because its mirror uses `cosign copy`, which
  #     carries the signature across in one op with no fresh readback);
  # (b) adopters `helm install` the chart the moment a release ships — a quarantine
  #     window on our own signed first-party chart is pure friction with no upside;
  #     trust here comes from the keyless cosign signature, not a quarantine/scan.
  # NOTE: with NO ScanPolicy the repo would inherit the 24h DEFAULT quarantine, so
  # this policy MUST exist to set 0.
  quarantineDuration: 0
  severityThreshold: high
  requireApproval: false
  provenanceMode: off
  scanBackends: []
  licensePolicy: {}
```
**Verify against the apply-time linter:** if `scanBackends: []` is rejected for a hosted repo,
fall back to `scanBackends: ["trivy"]` (kept with `quarantineDuration: 0`, so the chart is still
immediately available and trivy only records async — never blocks). The load-bearing field is
`quarantineDuration: 0`; the scan-backend choice is the adjustable part.

### 3. `deploy/ansible/files/gitops/auth/grants/gha-release-write-hort-charts.yaml`
Copy `gha-release-write-hort-oci.yaml`, `repository: hort-charts`, name `gha-release-write-hort-charts`.

### 4. `deploy/ansible/files/gitops/auth/grants/gha-release-read-hort-charts.yaml`
Copy `gha-release-read-hort-oci.yaml`, `repository: hort-charts`, name `gha-release-read-hort-charts`.
**Required** — the `cosign sign` step resolves the just-pushed chart manifest back, and write does
not imply read (same reason hort-oci has a read grant).

## Acceptance

- The four files parse + cross-validate: `cargo test --workspace` green (the
  `public_deploy_gitops_tree` / `alpha_fixtures` gitops-tree guards must pass with the new
  repo + policy + grants; confirm `scanBackends: []` clears the apply-time linter or fall back
  per above).
- `quarantineDuration: 0` present (not the 24h default).
- Both write + read grants for `gha-release` on `hort-charts`.
- No `.rs` changes expected.

## Deploy (operator — Tom, after merge)

Apply the updated gitops to registry.hort.rs (restart-to-apply for the quarantine field), then
re-run `docker-publish` — the chart-flavor publish + sign should complete. This is the last #60
Item-3 gap; once green, the self-contained-registry chart flavor is fully live.

### Starter prompt

```
/hort-architect

Implement backlog item 040 (issue #71) on branch agent/71-hort-charts-gitops-repo. Config-only,
no Rust. Add the 4 gitops files exactly as specified (hort-charts repository + scan policy with
quarantineDuration: 0 + gha-release write & read grants), modeled on the hort-oci files. Confirm
scanBackends: [] clears the apply-time gitops linter (fall back to ["trivy"] with quarantine 0 if
not). Run cargo test --workspace + fmt + clippy and confirm the gitops-tree parse guards pass.
Report per the handover protocol.
```
