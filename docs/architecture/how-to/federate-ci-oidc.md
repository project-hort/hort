# Federate CI runners (GitHub Actions, GitLab CI) to hort-server

This guide is for operators who want their CI/CD pipelines to push
artifacts to `hort` without storing a long-lived PAT in
the CI provider's secret store. Both GitHub Actions and GitLab CI
expose short-lived OIDC JWTs to job runners; hort-server treats both
as generic OIDC issuers and exchanges their tokens for an
hort-server bearer at `POST /api/v1/auth/exchange`.

For the design rationale see
[ADR 0018](../../adr/0018-auth-catalog-canonical.md) and the
federation entries in [`docs/auth-catalog.md`](../../auth-catalog.md).

---

## 1. What this gives you

Without federation, a typical CI pipeline keeps an hort-server PAT in
`secrets.HORT_TOKEN` (GitHub) or a masked CI/CD variable (GitLab).
That credential was long-lived, scoped at the user level rather
than per-workflow, opaque to audit, and rotated only when someone
remembered.

Federation flips all four: the CI provider mints a fresh JWT per
job, trust is declared per `(repository, environment, ref, …)`
claim shape, the `TokenIssued` event records
`source_issuer`/`source_sub`/`source_jti`, and the CI provider
rotates its own signing keys with hort-server picking up the new
JWKS automatically.

Existing PATs continue to work — adoption is per-workflow at the
operator's pace.

---

## 2. Common ground

Both providers issue short-lived OIDC JWTs that hort-server treats
identically. The provider mints a JWT with provider-specific
claims; the job posts it to `/api/v1/auth/exchange` with
`subject_token_type=urn:ietf:params:oauth:token-type:jwt`; the
server validates signature + audience + standard claims, matches
the claims against `ServiceAccount.federatedIdentities[].claims`,
and returns a short-lived bearer.

What differs: `OidcIssuer.spec.issuerUrl` (GHA has one global
issuer; GitLab CI's is per-instance) and the
`federatedIdentities[].claims` shape (GHA uses `repository`,
`environment`, `workflow`, `actor`; GitLab uses `project_path`,
`ref`, `ref_protected`, `user_email`). The exchange flow itself
is uniform — one hort-server deployment serves both providers
concurrently.

---

## 2a. The minimum-viable trust boundary (read before you write `claims`)

> **⚠️ Binding a federated `ServiceAccount` on `repository` /
> `project_path` *alone* is under-constrained — any pipeline or
> branch in that repo can assume it.**
>
> A repository/project claim says *which repo* the token came from.
> It says nothing about *which workflow*, *which branch*, or *which
> environment* minted it. Any job a contributor can run in that repo
> — a fork PR's CI, an unprotected feature branch, a hand-pushed
> `workflow_dispatch` — mints a JWT carrying the same
> `repository`/`project_path`. An FI constrained on that claim alone
> is therefore assumable by **every job in the repo**, not just the
> release pipeline you intended. `repository`/`project_path` is a
> *necessary* discriminator, never a *sufficient* trust boundary.
>
> **Remediation — apply both:**
>
> 1. **Pin `aud`** to the exact value in your
>    `OidcIssuer.spec.audiences` list (set it as the `audience=`
>    JWT-fetch parameter on GHA / the `id_tokens[].aud` on GitLab,
>    and match it in the FI). This binds the token to *this*
>    relying party so a token minted for a different `aud` cannot
>    assume the SA. **AND**
> 2. **Add at least one** discriminating claim alongside the
>    repository/project claim:
>    - **GitHub:** one (or more) of `ref` / `environment` /
>      `workflow` / `job_workflow_ref` (`job_workflow_ref` is the
>      strongest — see §8 "Pin `job_workflow_ref` for release
>      pipelines").
>    - **GitLab:** `ci_config_ref_uri`, or `ref` **plus**
>      `ref_protected: 'true'` (and `environment` when the job
>      declares one).
>
> `repository` + `aud` + `ref` (or `environment`/`workflow`/
> `job_workflow_ref`) is the floor. The §3b/§4b examples below and
> the §8 release-pipeline guidance all satisfy it; do not declare an
> FI that does not.
>
> **This is the same condition the binary warns you about.** At
> gitops `apply`, hort-server runs an **under-constrained
> federated-identity check** (an apply-time WARN — fail-loud,
> not silent). An FI that
> names a `repository`/`project_path` claim **without** any of
> `ref` / `environment` / `workflow` / `aud` emits this `warn!`
> (apply still succeeds — a repo-only policy is a footgun, not a
> schema error, and a single-tenant repo may legitimately accept the
> residual risk):
>
> ```text
> WARN gitops apply: under-constrained federatedIdentities —
>   ServiceAccount `<name>` federatedIdentities[<idx>] (issuer
>   `<issuer>`) constrains only a repository/project claim without a
>   discriminating ref/environment/workflow/aud — any workflow in
>   that repo can assume this identity. Add a discriminating claim
>   (e.g. `ref`, `environment`, `workflow`) or pin `aud` (audit F-7).
> ```
> (structured fields: `service_account`, `federated_identity_index`,
> `issuer`).
>
> If you see this WARN in `kubectl logs … deploy/hort-server` after an
> apply, **this section is the fix.** It is a warning, not a hard
> rejection — so it will not block your apply; it is on you to
> narrow the FI before the SA is used.

---

## 3. GitHub Actions

### 3a. Declare the `OidcIssuer`

```yaml
apiVersion: project-hort.de/v1beta1
kind: OidcIssuer
metadata:
  name: github-actions
spec:
  issuerUrl: https://token.actions.githubusercontent.com
  audiences: [hort-server]
  jwksRefreshInterval: 1h
  allowedAlgorithms: [RS256]
```

`issuerUrl` is the same for every GitHub-hosted runner globally;
self-hosted runners hosted on github.com use the same issuer. GHE
Server runs its own issuer at the GHE instance's URL — adjust
accordingly.

### 3b. Declare the `ServiceAccount`

The most common claim discriminator pair is `(repository,
environment)`. Use environments (the GitHub feature, not
arbitrary strings) to bind production-push capability to the
`production` environment, requiring its approval rules:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: gha-myorg-myrepo-prod-pypi
spec:
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: github-actions
      claims:
        repository: my-org/my-repo
        environment: production
```

Other useful claim discriminators when `environment` is not in
play: `ref: refs/heads/main` restricts to `main` pushes;
`workflow: Release` restricts to the `Release` workflow file;
`job_workflow_ref: my-org/my-repo/.github/workflows/release.yml@refs/heads/main`
pins the workflow's full origin including ref (best for
release-grade pipelines). `actor` is a poor discriminator —
`workflow_dispatch` runs carry the dispatcher's username, making
per-user matching brittle.

### 3c. The workflow file

End-to-end example pushing a wheel to a Hosted PyPI repository:

```yaml
name: Release wheel
on:
  push:
    branches: [main]

permissions:
  id-token: write          # required for the OIDC token
  contents: read

jobs:
  publish:
    runs-on: ubuntu-latest
    environment: production    # gates token claims as well as approvals
    steps:
      - uses: actions/checkout@v4

      - name: Build wheel
        run: |
          pip install build
          python -m build --wheel

      - name: Exchange OIDC token for hort-server bearer
        id: hort-auth
        env:
          HORT_BASE_URL: https://hort.example.com
        run: |
          JWT=$(curl -sS \
            -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=hort-server" \
            | jq -r .value)
          RESPONSE=$(curl -sS -X POST \
            "${HORT_BASE_URL}/api/v1/auth/exchange" \
            -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
            -d "subject_token=${JWT}" \
            -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt")
          HORT_TOKEN=$(echo "${RESPONSE}" | jq -r .access_token)
          echo "::add-mask::${HORT_TOKEN}"
          echo "hort_token=${HORT_TOKEN}" >> "$GITHUB_OUTPUT"

      - name: Push wheel via twine
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ steps.hort-auth.outputs.hort_token }}
        run: |
          pip install twine
          twine upload \
            --repository-url https://hort.example.com/pypi/pypi-internal/ \
            dist/*.whl
```

Notes:

- `permissions: id-token: write` is the only token GHA needs from
  the workflow author — it enables the
  `ACTIONS_ID_TOKEN_REQUEST_*` env vars on the runner.
- `audience=hort-server` on the JWT-fetch URL matches the
  `audiences:` list on the `OidcIssuer`. Misspelling this is the
  most common cause of an `aud_mismatch` deny.
- `::add-mask::` keeps the bearer out of subsequent log output.

For other client tools, replace the twine call:

- `npm publish` — `npm config set //hort.example.com/npm/npm-internal/:_authToken "${HORT_TOKEN}"` then `npm publish`.
- `cargo publish` — `cargo publish --token "${HORT_TOKEN}" --registry hort-internal` (with a `[registries.hort-internal]` entry in `~/.cargo/config.toml`).
- `docker push` — `echo "${HORT_TOKEN}" | docker login hort.example.com -u oauth --password-stdin && docker push hort.example.com/oci-internal/myimage:1.0`.

---

## 4. GitLab CI

### 4a. Declare the `OidcIssuer`

The `issuerUrl` is the GitLab instance's base URL. For
`gitlab.com`:

```yaml
apiVersion: project-hort.de/v1beta1
kind: OidcIssuer
metadata:
  name: gitlab-com
spec:
  issuerUrl: https://gitlab.com
  audiences: [hort-server]
  jwksRefreshInterval: 1h
  allowedAlgorithms: [RS256]
```

For a self-hosted instance, substitute the instance hostname
(`https://gitlab.example.com`). GitLab serves JWKS at
`/oauth/discovery/keys`; hort-server discovers this from
`/.well-known/openid-configuration` at the issuer URL.

### 4b. Declare the `ServiceAccount`

GitLab's claim shape is project-centric. Match on `project_path`
+ `ref`; if you only want protected-branch pushes to qualify, add
`ref_protected: 'true'`:

```yaml
apiVersion: project-hort.de/v1beta1
kind: ServiceAccount
metadata:
  name: glci-myorg-myrepo-pypi
spec:
  role: developer
  repositories: [pypi-internal]
  federatedIdentities:
    - issuer: gitlab-com
      claims:
        project_path: my-org/my-repo
        ref: main
        ref_protected: 'true'
```

Note `'true'` is a string — JWT claim values are typically
strings even when they represent booleans. The exact-match
comparison is on string equality.

Other useful claims:

- `environment: production` — when the job declares `environment:`
  matching a GitLab Environment.
- `user_email: deploy-bot@example.com` — when the runner is
  invoked by a specific deploy bot account.

### 4c. The `.gitlab-ci.yml`

```yaml
stages: [publish]

publish:wheel:
  stage: publish
  image: python:3.12
  id_tokens:
    HORT_JWT:
      aud: hort-server
  variables:
    HORT_BASE_URL: https://hort.example.com
  rules:
    - if: '$CI_COMMIT_REF_NAME == "main"'
  script:
    - pip install build twine
    - python -m build --wheel
    - |
      RESPONSE=$(curl -sS -X POST \
        "${HORT_BASE_URL}/api/v1/auth/exchange" \
        -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        -d "subject_token=${HORT_JWT}" \
        -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt")
      export HORT_TOKEN=$(echo "${RESPONSE}" | jq -r .access_token)
    - |
      twine upload \
        --repository-url "${HORT_BASE_URL}/pypi/pypi-internal/" \
        --username __token__ \
        --password "${HORT_TOKEN}" \
        dist/*.whl
```

Notes:

- The `id_tokens:` block at job level is the GitLab feature that
  mints the JWT — its `aud:` value must match the
  `OidcIssuer.spec.audiences` list.
- `${HORT_JWT}` is provided automatically by the runner; there is
  no equivalent of GHA's two-env-var fetch.
- `jq` is the only tool not in the standard `python:3.12` image;
  add `apt-get install -y jq` if needed, or use `python -c
  "import json,sys; print(json.load(sys.stdin)['access_token'])"`.

---

## 5. Claim shape reference

Quick reference for the most useful claims, per provider.

### GitHub Actions

| Claim | Meaning | When to match |
|---|---|---|
| `repository` | `owner/repo` | Per-repo isolation. Almost always required. |
| `repository_owner` | `owner` | Org-wide identity (rare; prefer per-repo). |
| `environment` | Environment name | Gates on the GitHub Environment + its approval rules. |
| `ref` | Full ref (`refs/heads/main`, `refs/tags/v1.0`) | Restrict to specific branches or tags. |
| `actor` | Triggering user's login | Generally avoid — brittle on `workflow_dispatch`. |
| `workflow` | Workflow file's `name:` | Workflow-specific identity. |
| `job_workflow_ref` | Full workflow-file path + ref | Strongest pinning for release pipelines. |

### GitLab CI

| Claim | Meaning | When to match |
|---|---|---|
| `project_path` | `group/subgroup/project` | Per-project isolation. Almost always required. |
| `ref` | Branch or tag name (no `refs/heads/` prefix — just `main`) | Restrict to specific branches. |
| `ref_protected` | `'true'` / `'false'` (string) | Restrict to protected-branch pushes. |
| `ref_type` | `'branch'` / `'tag'` | Distinguish tag pushes from branch pushes. |
| `environment` | GitLab Environment name | Gates on environment + its protection rules. |
| `user_email` | Triggering user's email | Tie identity to a deploy-bot account. |
| `iid` | Internal pipeline iid | Generally avoid — high-cardinality. |

Both providers publish authoritative claim references at their
own docs;
[GitHub OIDC claim reference](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token)
and
[GitLab OIDC ID token claims](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html).

---

## 6. Verify it works

Run the workflow / pipeline once. On success:

```bash
kubectl logs -n hort-server deploy/hort-server | grep TokenIssued | tail -1
```

Expect to see `source_issuer = "github-actions"` (or
`"gitlab-com"`), `source_sub` matching the JWT's `sub` claim, and
`source_jti` populated. The metric
`hort_token_exchange_total{kind="federated_jwt", result="success"}`
ticks on every successful exchange.

A negative check: drop a wrong claim into the `ServiceAccount`
(`environment: nonexistent`), re-run, and confirm a `403` with
`reason="no_sa_match"` in hort-server's `tracing::info!`. The CI
job should fail at the `curl` step with a non-success HTTP
status.

---

## 7. Troubleshooting

The deny taxonomy is the same as the k8s recipe; see
[`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md)
§8 for the table. Provider-specific gotchas:

### `unknown_issuer` (GitHub)

The `iss` claim of the GHA JWT is
`https://token.actions.githubusercontent.com` for every
github.com-hosted job, regardless of the repository. If you see
`unknown_issuer`, the `OidcIssuer.spec.issuerUrl` is the wrong
string — most often a trailing slash or `http://` typo.

### `unknown_issuer` (GitLab self-hosted)

The `iss` claim is the GitLab instance's URL exactly as the
operator configured it (`https://gitlab.example.com`, no trailing
slash). Mismatches against `OidcIssuer.spec.issuerUrl` produce
`unknown_issuer`. Cross-check via
`curl https://gitlab.example.com/.well-known/openid-configuration |
jq .issuer`.

### `aud_mismatch`

GHA: the `audience=` query parameter on
`${ACTIONS_ID_TOKEN_REQUEST_URL}` is wrong. GitLab: the `aud:`
under the `id_tokens:` block is wrong. Both must appear in the
`OidcIssuer.spec.audiences` list verbatim.

### `no_sa_match`

The JWT validated but no `ServiceAccount.federatedIdentities[]`
matched. Decode the JWT (`jq -R 'split(".") | .[1] |
@base64d | fromjson'`) and compare its claims to your envelope
character by character. GHA's `repository` is `owner/repo`;
GitLab's `project_path` includes any subgroups (`group/subgroup/repo`).

### `multiple_sa_match`

Two envelopes' claim sets are both subsets of the same JWT's
claims. Add a discriminator to one envelope (e.g. tighten
`environment` or `ref`) so the match is unambiguous. hort-server
logs the SA-name candidates at INFO; check the log to see which
envelopes are conflicting.

### `signature_invalid`

Either the JWKS cache is stale (lower `jwksRefreshInterval` to
`5m` and re-run), or the JWT was signed by a different issuer
than its `iss` claim names. The latter is rare in practice but
indicates a CI provider misconfiguration; open a support ticket
with them.

---

## 8. Security considerations

**Exact-match claim selection is safer than regex.** Regex
matching is deliberately excluded: every claim-value comparison
is byte-equality. Regex extraction (e.g. `repository: ^my-org/.+`)
would let one envelope cover an entire org, which becomes a
privilege-creep liability when the org grows past the original
operator's mental model. The exact-match constraint forces every
covered repository to be explicitly named — discoverable in the
gitops history, reviewable, and revocable line by line.

**Narrow each `ServiceAccount` to one workflow scope.** One
envelope per `(repository, environment)` or `(project_path,
ref)` tuple. Reusing an envelope across multiple workflows
collapses the audit trail and makes per-workflow revocation
impossible — the `TokenIssued` event records `source_sub` and
`source_jti`, but the hort-server identity it bound to is the same
across all of them.

**Never re-use a federated identity for human use.** A
`ServiceAccount`'s backing user has `is_service_account = true`
and is invisible to `/users/me` flows. Don't try to share it
with an interactive operator workflow — that defeats both the
short-lifetime guarantee and the per-workflow audit attribution.

**Pin `job_workflow_ref` for release pipelines.** For pipelines
that mint production artifacts, match on `job_workflow_ref`
(GHA) or the combination of `project_path` + `ref` +
`ref_protected: 'true'` (GitLab). These are the strongest
discriminators the providers offer and they prevent a forked PR
or an unprotected-branch push from forging a release-grade
token.

---

## 9. See also

- [`docs/auth-catalog.md`](../../auth-catalog.md) — the canonical
  auth-surface catalog, including the federation/exchange entries.
- [`federate-k8s-workload-identity.md`](./federate-k8s-workload-identity.md)
  — the same pattern for k8s pods using projected SA tokens.
- [`rotating-service-account-tokens.md`](./rotating-service-account-tokens.md)
  — fallback PAT rotation for runners that cannot do OIDC.
- [`declare-gitops-config.md`](./declare-gitops-config.md)
  `kind: OidcIssuer` + `kind: ServiceAccount` — canonical
  envelope reference.
