# CI integration with hort quarantine

How this repo's GitHub Actions build against hort's quarantine gate with minimal
friction, and the security posture that makes it safe.

## The model

| Trigger | Source | Purpose |
|---|---|---|
| **feature-branch push** (`feature-ci.yml`) | original upstreams (crates.io) | fast iteration, unblocked by quarantine; **also prefetches** the resolved deps into hort to start the quarantine clock early |
| **pull_request → main / develop / release/** (`ci.yml`) | **hort** (`registry.hort.rs`) | the supply-chain gate — dependencies must clear quarantine (released, scanned-clean) before merge |
| push to protected (post-merge) | upstream | already gated at the MR; no re-gate needed |

**Prefetch-early is the friction killer.** Because feature-branch pushes prefetch
the dependency set (hort cascades transitively), a new dependency's quarantine
window usually elapses *before* the merge build runs — so the gate rarely blocks.

## The dependency gate + triage

The merge gate is the **`hort-deps-gate`** job: on a same-repo MR it resolves the
locked dependency set from hort (`cargo fetch --locked`). If a dependency is still
quarantined or was rejected, the fetch fails → **the gate goes red** and the build
jobs skip (`needs: hort-deps-gate`). Make `hort-deps-gate` a **required status
check** so quarantine actually blocks the merge — a *green* gate always means the
code built against a clean dependency set (quarantine never produces a green gate).

On a red gate, `hort-quarantine-triage` posts one diagnostic PR comment (it does
**not** change status — the resolve failure already reds the gate), keyed on
hort's authoritative discovery status (`DiscoveryVersionStatus.kind`):

| `kind` | Meaning | Comment |
|---|---|---|
| `quarantined` | inside the time window | ⏳ retryable — re-run after `quarantine_until` |
| `quarantined_awaiting_release` | window elapsed, no release authority fired (ADR 0007) | 🟠 **stuck** — a timed retry won't help; needs a curator waive / admin override |
| `rejected` / `scan_indeterminate` | scanned & blocked | 🔴 do not retry — the gate working as intended |
| `unknown` | not yet ingested | ❔ prefetch didn't cover it; ingests on first fetch |
| _(none of the above)_ | network / lockfile drift / missing crate | gate stays red; not quarantine-related |

Underlying status contract (`hort-http-core` per-artifact filter): quarantined →
`503` (transient), rejected / scan-indeterminate → `404` (terminal).

## Security posture (why this is safe)

The threat is a PR that mints or abuses the hort credential — including a PR that
**edits the workflow YAML itself** (a `pull_request` run uses the workflow from
the PR head). Controls, in order of load-bearing-ness:

1. **Fork PRs cannot mint the token.** The MR gate's hort steps are `if:`-gated on
   `github.event.pull_request.head.repo.full_name == github.repository` (same-repo
   only). GitHub also withholds secrets and caps permissions for fork-PR runs.
   **Enable the belt-and-suspenders repo setting** so an edited fork workflow does
   not even run unapproved — see the checklist below.
2. **The token is low-blast-radius.** Federation mints a **short-lived,
   read + prefetch-only, non-admin `ServiceAccount` bearer** — its cap
   snapshots the SA's grants at exchange (ADR 0044); service accounts cannot
   be admin (ADR 0038). Even if a same-repo PR's run leaked it, it buys "pull
   deps + prefetch" for minutes, and it is audited
   (`hort_fed_sa_match_total`, the federation log).
3. **`push`-only prefetch.** The write-ish prefetch capability runs only on `push`
   (trusted members; forks cannot push here) — never a `pull_request` /
   `pull_request_target` trigger.
4. **The `if:` gate is defense-in-depth, not the boundary** — a PR owns its own
   workflow file and can remove the gate. The boundaries are #1 (platform
   fork-run controls) and #2 (token scope).
5. **SHA-pinned third-party actions** (they run in the privileged context).

### Recommended repo settings

- [ ] **Settings → Actions → Fork pull request workflows → "Require approval for all outside collaborators"** (or stricter). Contains fork-PR workflow edits.
- [ ] **`HORT_PROXY_ENABLED` repo variable = `true`** only once the instance is live. Everything is a no-op until then.
- [ ] **Make `hort-deps-gate` a required status check** on main / develop, so a quarantined/rejected dependency (red gate) actually blocks the merge until it clears + a re-run passes.
- [ ] **CODEOWNERS + required review** on `.github/` (see `.github/CODEOWNERS`) — or a **push ruleset restricting `.github/workflows/**`** with a maintainers **bypass** — to gate *merges* of workflow changes. (On a single-maintainer repo, use the ruleset-with-bypass form; required-review would block your own PRs.)
- [ ] Keep third-party actions **SHA-pinned**.
- [ ] (Optional, closes the same-repo-rogue case) a **GitHub Environment with a required reviewer** on the token-minting jobs.

## The hort side — a read + prefetch ServiceAccount (gitops)

Declare an identity-only service account for GitHub Actions, federated on the
GitHub OIDC issuer, constrained by a **discriminating claim** (`repository`
alone is flagged by hort's under-constrained-FI linter — see
`docs/architecture/how-to/federate-ci-oidc.md`), with its authority as
explicit grants alongside:

```yaml
apiVersion: project-hort.de/v1
kind: ServiceAccount
metadata:
  name: github-ci
spec:
  federatedIdentities:
    - issuer: github-actions          # OidcIssuer metadata.name
      # repository + a discriminator (aud is server-config, not attacker-set).
      claims:
        repository: project-hort/hort
        aud: hort-server
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: github-ci-read
spec:
  subject:
    kind: serviceAccount
    name: github-ci        # → GrantSubject::User(backing_user_id) at apply (ADR 0037)
  permission: read         # pull + discovery; no curate/admin
  # repository omitted = global; scope per-repo per your layout
---
apiVersion: project-hort.de/v1
kind: PermissionGrant
metadata:
  name: github-ci-prefetch
spec:
  subject:
    kind: serviceAccount
    name: github-ci
  permission: prefetch     # permissions are flat — read does not imply prefetch
```

Audience `hort-server` is mandatory (`OidcIssuer.audiences` validates it; the CI
mints the OIDC token with `core.getIDToken('hort-server')`).

**The `PermissionGrant`s are the SA's entire authority.** The envelope declares
only who may assume the account; the exchanged bearer's cap is a snapshot of
the SA's effective grants at exchange time (ADR 0044), and effective authority
= grants **∩** cap (ADR 0036). Without the grants above, the exchange mints a
bearer that authorizes nothing — discovery + prefetch fail **closed** with a
`403` that does **not** name the missing capability. Apply the SA **and** its
grants together.
