# Self-contained registry chart — backlog (issue #60)

Branch-local (D7). PR-sized items, dependency-ordered. Design: `docs/plans/self-contained-registry-chart.md`.

Items 1–3 are independent and can land in any order; Item 4 (the published second flavor) depends on Item 1 (the chart mechanism) and Item 2 (the `hort-base` repo). Item 0 is a hard security precondition and is filed as its own issue so it lands ahead of everything.

---

## Item 0 — (precondition) Stop the GitHub hort-auth action echoing the exchange response

**Filed separately** as its own `agent:task` security issue — it is a real bug independent of #60 and must land before `HORT_PROXY_ENABLED` goes to production.

**Design doc section:** §1 (sweep), §6 invariant 1
**Read first:** `.github/actions/hort-auth/action.yml` (line 95)
**Acceptance:** the exchange-error path no longer echoes `${response}`; it emits a body-free message, mirroring the already-fixed GitLab `.hort_auth` (`echo "… (omitted)"`). No auth-exchange response body reaches CI logs on any path.

---

## Item 1 — Chart `global.imageRegistry` (helper-owned rewrite, empty default)

**Design doc section:** §3 D1
**Read first:** `deploy/helm/hort-server/templates/_helpers.tpl` (`hort-server.image` :64, `hort-server.worker.image` :102), `deploy/helm/hort-server/values.yaml` (`image.repository` :23, `worker.image.repository` :899, `auth.dex.image` :227)
**Acceptance:**
1. New `global.imageRegistry` value, default `""`, documented in `values.yaml`.
2. `hort-server.image` / `hort-server.worker.image` rewrite to `<reg>/hort-oci/hort-<component>:<tag>` when set; unchanged (`.Values.*.repository:<tag>`) when empty.
3. A new `hort-server.dex.image` helper owns the dex mapping (`<reg>/hort-base/dex:<pin>` when set; `.Values.auth.dex.image` when empty); every dex image reference goes through it.
4. `helm template` with `global.imageRegistry` **unset** is byte-identical to today (regression proof — diff against the current render).
5. `helm template` with `global.imageRegistry=registry.hort.rs` renders all three images under `registry.hort.rs`.
6. The existing `quality:helm-template-test` job passes.

### Starter prompt

/hort-architect

Implement Item 1 of `docs/plans/self-contained-registry-chart-backlog.md` (issue #60). Read design §3 D1 and the three helper/values locations. Add `global.imageRegistry` (empty default) and route all three image refs (server, worker, dex) through helpers that rewrite only when it is set. The load-bearing property is that an unset value renders byte-identically to today — prove it with a `helm template` diff. Do not add per-component repository overrides; the helper owns the `hort-oci`/`hort-base` split.

---

## Item 2 — `hort-base` gitops repo + gha-release write grant + scan policy

**Design doc section:** §3 D2
**Read first:** `deploy/ansible/files/gitops/repositories/hort-oci.yaml`, `deploy/ansible/files/gitops/policies/hort-oci-scan.yaml`, `deploy/ansible/files/gitops/auth/grants/gha-release-write-hort-oci.yaml`
**Acceptance:**
1. `repositories/hort-base.yaml` — `format: oci`, `type: hosted`, `isPublic: true`, filesystem CAS at `/var/lib/hort-server/cas/hort-base`.
2. `auth/grants/gha-release-write-hort-base.yaml` — serviceAccount-subject write grant, twinning the hort-oci one.
3. `policies/hort-base-scan.yaml` — **per D2's confirmed decision** (recommend D2-a: trivy on, `severityThreshold: critical`, with an inline comment recording that we cannot remediate third-party base images so a hold degrades only the mirror, with upstream as the containerd fallback).
4. All three parse and cross-validate through `hort_config::DesiredState::parse_files` + `.validate()` (the `alpha_fixtures.rs` pattern); the full ansible gitops tree still validates.

### Starter prompt

/hort-architect

Implement Item 2 of `docs/plans/self-contained-registry-chart-backlog.md` (issue #60). Twin the `hort-oci` gitops set (repo + gha-release write grant + scan policy) as `hort-base` for pinned third-party base images (dex, postgres). Read design §3 D2 for the scan-policy decision — confirm D2-a vs D2-b with the architect before writing the policy. Validate through the real hort-config parse+validate pipeline.

---

## Item 3 — CI: `mirror-to-hort-base` + second (registry.hort.rs) chart flavor

**Design doc section:** §3 D3, §6 invariants 2 & 4
**Read first:** `.github/workflows/docker-publish.yml` (`mirror-to-hort-oci` :340, `publish-chart`), the #47 keyless chart-signing steps
**Acceptance:**
1. `mirror-to-hort-base` job — `cosign copy --force` the **digest-pinned** `dex` + `postgres` refs → `registry.hort.rs/hort-base/{dex,postgres}:<tag>`, same `HORT_PROXY_ENABLED` gate + `hort-auth` action + `gha-release` SA as `mirror-to-hort-oci`. Sources digest-pinned, not tag-floating.
2. `publish-chart` extended to publish a **second** chart copy to `registry.hort.rs/hort-charts/hort-server` with `global.imageRegistry` defaulted to `registry.hort.rs`, keyless-signed (#47).
3. The ghcr chart flavor is unchanged (`global.imageRegistry` empty). One source tree, two published defaults — a package-time `--set`/values override, never a forked chart.
4. Acceptance-verifiable: a mirrored image and the mirrored chart carry cosign signatures verifying against the same identity as the ghcr copies (§6 invariant 2).

### Starter prompt

/hort-architect

Implement Item 3 of `docs/plans/self-contained-registry-chart-backlog.md` (issue #60). Twin `mirror-to-hort-oci` for the base images and extend `publish-chart` for the second self-contained-defaults chart flavor. Read design §3 D3. Digest-pin the base-image sources; preserve cosign signatures on both the mirrored images and the mirrored chart (#47 keyless). Depends on Items 1 and 2.

---

## Item 4 — Postgres option (b): example values + how-to

**Design doc section:** §3 D4
**Read first:** `deploy/helm/hort-server/examples/` (existing example pattern), `values.yaml` postgres/DB section
**Acceptance:**
1. `deploy/helm/hort-server/examples/registry-hort-rs/values.yaml` — `global.imageRegistry: registry.hort.rs`, external postgres pointed at `registry.hort.rs/hort-base/postgres`.
2. `docs/architecture/how-to/self-contained-registry-install.md` — the operator recipe: `helm install oci://registry.hort.rs/hort-charts/hort-server` with defaults, everything resolves sovereign, **no node `registries.yaml`**.
3. The example renders (`helm template -f examples/registry-hort-rs/values.yaml`).

### Starter prompt

/hort-architect

Implement Item 4 of `docs/plans/self-contained-registry-chart-backlog.md` (issue #60). Ship the registry.hort.rs example values + the Diátaxis how-to (design §3 D4). Chart stays external-DB — option (a) bundled-postgres subchart is out of scope (§5). Depends on Item 1.

---

## Deferred (out of scope, §5)

- **Option (a) bundled-postgres subchart** — future single-install-demo initiative.
- **ADR + how-to distillation** (D7): before merge to main, distill the design into proposed **ADR 0051** and delete the plan docs.
