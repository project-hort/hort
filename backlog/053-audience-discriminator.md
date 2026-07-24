# 053 — #82: audience-based OIDC discrimination (drop the environment:ci deployment noise)

**Issue:** #82 (design + code-verification on the issue)
**Read first:** `crates/hort-http-core/src/handlers/exchange.rs::evaluate_fi` (~1535 — the
first-class `aud` selector, binds to the resolved audience),
`deploy/ansible/files/gitops/auth/issuers/github-actions.yaml` (`audiences` allow-list),
`auth/service-accounts/gha-ci.yaml` + `gha-release.yaml`,
`.github/workflows/{ci,feature-ci,prefetch-warm,release,docker-publish}.yml` (every
audience/`environment:` call site), `.github/actions/hort-auth/` (the composite action),
`docs/architecture/how-to/federate-ci-oidc.md`.

## Design (settled on #82; zero hort code changes — config + workflows only)

Discriminate `gha-ci` vs `gha-release` by **requested OIDC audience** instead of the
`environment` claim, killing the GitHub deployment records that `environment: ci` mints on
every CI run.

## The no-outage migration shape (load-bearing)

`federatedIdentities` is an **array**, and one matching FI suffices — so **each SA carries
BOTH identities during migration**:

- `gha-ci`: legacy FI `{repository, environment: ci}` **+** new FI
  `{repository, aud: hort-server-ci}`.
- `gha-release`: legacy FI `{repository, environment: release}` **+** new FI
  `{repository, environment: release, aud: hort-server-release}` (environment stays — it's
  a real protected env; belt-and-suspenders).

Old workflows (aud `hort-server`) and new (per-class audiences) both match throughout;
cross-SA disjointness holds in every combination (verify: a CI token can never match
gha-release's FIs and vice versa, old or new). Cleanup (dropping legacy FIs, narrowing
`audiences`, deleting the GitHub `ci` environment) is a **separate follow-up after** the
deploy + github-public sync are both live — NOT this change.

## Scope

1. **Gitops:** issuer `audiences: ["hort-server", "hort-server-ci", "hort-server-release"]`;
   the two SAs gain their second FI per above (comments explaining the migration + the #82
   rationale; update gha-ci.yaml's #64-era NOTE). Gitops-tree guards must pass.
2. **Workflows:** the six CI jobs (`ci.yml` ×5 via hort-auth, `feature-ci.yml` inline)
   **drop `environment: ci`** and request audience `hort-server-ci`; `prefetch-warm.yml`
   (inline) → `hort-server-ci`; the four release jobs (hort-auth) → `hort-server-release`
   (keep `environment: release`). The `hort-auth` composite action gains a required
   `audience` input (no silent default — every caller states its class); update every
   invocation. `actionlint` the results (**/tmp/actionlint** exists in the sandbox).
3. **Docs:** `federate-ci-oidc.md` to the audience model; the #64-era comments in the six
   jobs + gha-ci.yaml updated (reference #82).
4. **Explicitly NOT here:** the cleanup MR (legacy-FI removal etc. — follow-up once live),
   any hort `.rs` change (none needed — verified), touching `environment: release`.

## Acceptance

- Gitops parses + cross-validates; both SAs have 2 FIs each; disjointness argued in the MR
  (all four token shapes × both SAs).
- No `environment: ci` remains anywhere in the workflows; every hort-auth/getIDToken call
  site states its audience explicitly; actionlint clean.
- Docs updated. Full gate green (no `.rs` expected — run it).

### Starter prompt

```
/hort-architect

Implement backlog item 053 (issue #82) on branch agent/82-audience-discriminator.
IMPORTANT: verify `git branch --show-current` before every commit — never develop.
Config+workflows only (verified: evaluate_fi already supports the aud selector). Gitops:
widen the github-actions issuer audiences to [hort-server, hort-server-ci,
hort-server-release]; give gha-ci AND gha-release a SECOND federatedIdentity per the
backlog's no-outage migration shape (legacy FI stays). Workflows: six CI jobs drop
environment:ci + request audience hort-server-ci (hort-auth action gains a REQUIRED
audience input; update all callers incl. release→hort-server-release; feature-ci +
prefetch-warm inline getIDToken too). Do NOT remove the legacy FIs or touch
environment:release (cleanup is a follow-up). actionlint everything; gitops guards green;
argue the four-token-shapes disjointness in the report. Full gate; report per the handover
protocol.
```
