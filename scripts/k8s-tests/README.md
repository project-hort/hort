# k8s-tests — kind/Kubernetes smokes

These two smokes require a `kind` (Kubernetes-in-Docker) cluster. They are a
separate suite from both the containerized `scripts/native-tests/` runner and the
host-side `scripts/host-tests/` runner.

## Scripts

| Script | Purpose |
|---|---|
| `test-gitops-k8s-configmap.sh` | Asserts that gitops boot correctly loads files from a Kubernetes ConfigMap volume mount (the two-level symlink projection pattern `..data/` → `..timestamp/`) — regression test for commit 243c9b0 where the directory walker did not follow those symlinks and reported `files_loaded: 0`. |
| `test-k8s-rotation.sh` | ServiceAccount fallback PAT-rotation end-to-end smoke — installs the Helm chart in a real kind cluster with rotation enabled, fires the rotation CronJob, and asserts the managed Secret is upserted with the canonical labels and annotation. |

## Prerequisites

- [`kind`](https://kind.sigs.k8s.io/) — Kubernetes-in-Docker
- `kubectl`
- `helm` (v3)
- `docker`

These tests do **not** use `deploy/compose/docker-compose.yml`; each script spins
up its own kind cluster (or uses an existing one) and tears it down on exit.
Expect ~5 minutes of runtime per script (cluster spin-up + Helm install + CronJob
tick).

Run on demand from the repo root:

```bash
bash scripts/k8s-tests/test-gitops-k8s-configmap.sh
bash scripts/k8s-tests/test-k8s-rotation.sh
```

## See also

- `scripts/native-tests/README.md` — containerized client/db/cli scenarios.
- `scripts/host-tests/README.md` — host-side compose orchestration smokes.
