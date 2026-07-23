# 050 — #77: hort.rs — self-hosted CLI page + user docs + permanent version archive

**Issue:** #77 (design settled — see the issue's pivot notes; #78's foundation is merged)
**Read first:** `site/` + `scripts/site/{mdconv,generate,linkcheck}.py` + `scripts/build-site.sh`
(the #78 generator/pipeline — REUSE it, don't fork it), `deploy/ansible/roles/website/` (the
#78 role — hort.rs is a second deployment of the same machinery),
`install/` (`index.html`, `install-cli.sh`, `.ps1`, `cosign.pin` — the apex contract),
`.github/workflows/install.yml` (the Pages job to retire),
`docs/architecture/how-to/{install-cli,cli-completions,using-hort-cli-with-admin-ops}.md` +
`crates/hort-cli/README.md` (the user-docs sources).

## Design contract (settled)

Same rules as #78: fully static, single-source from the repo's md, dependency-light pinned
tooling, ansible-deployed. Plus two hort.rs-specific invariants:
- **Apex script contract:** `https://hort.rs/install-cli.sh`, `/install-cli.ps1`,
  `/cosign.pin` keep their exact paths (published URLs; the installer scripts reference them).
- **Archive immutability:** `hort.rs/dl/<tag>/` is append-only — a published version is never
  overwritten or deleted.

## Scope

### A. Site content (extend the #78 generator — one pipeline, two sites)
- **CLI landing page** (`hort.rs/`): what hort-cli is (pure HTTP client), install one-liners
  (sh + PowerShell), the **fail-closed verification story** (SHA-256 + keyless cosign, no
  skip — it's a differentiator, show it), manual-download path (→ `/dl/` + the `cosign
  verify` command mirroring `install-cli.md`), links → project-hort.de, GitHub, the docs.
- **CLI user docs** generated from the four md sources above (same generator; same link
  rules — in-scope → site-relative, out-of-scope → GitHub).
- The installer files (`install-cli.sh`, `.ps1`, `cosign.pin`) are copied into the built
  tree at the apex. Extend `scripts/build-site.sh` (or a thin second entry point) to build
  BOTH sites; the CI `quality:site-build` job covers both.

### B. Version archive (`/dl/`)
- **Layout:** `dl/<tag>/<assets>` + the release's checksums/signature material +
  `dl/index.html` (static version index, newest first) + optionally `dl/latest` info. Assets
  = the CLI release archives (what `install-cli.sh` downloads today from GitHub Releases).
- **Population (host-side, ansible):** a committed script the `website`-role deployment runs
  (or a dedicated task) that, for each published `v*` release on GitHub, downloads the
  assets **into `dl/<tag>/` only if that dir doesn't already exist** (immutability), and
  **verifies each asset against `cosign.pin` + checksums before placing it** (fail-closed
  backfill — never serve an unverified binary). Backfills the whole published history on
  first run; adds new tags on subsequent runs. Needs network on the host (GitHub) — that's
  fine, it's the operator's deploy step, not the site build.
- **NOT in this item:** flipping `install-cli.sh`'s `DL_BASE` default to `hort.rs/dl` —
  that's the deliberate step 2 (separate change, after the archive is live + verified).

### C. Ansible + retirement
- Deploy hort.rs as a **second vhost via the existing `website` role** (parameterize the
  role for multiple sites — domain + content dir — rather than copy-pasting a sibling role;
  `site-website.yml` grows the second site).
- Certbot: add the `hort.rs` domain (the #78 parameterization supports per-invocation fqdn).
- **Retire `install.yml`'s ready-but-gated GitHub-Pages deploy job** (and its
  `INSTALLER_PAGES_LIVE` gating comments) — one canonical home. The installer lint/test
  jobs in that workflow STAY (they gate the scripts themselves).

## Acceptance

- Build produces both sites; hort.rs tree has the CLI landing + user docs + the apex
  scripts at their exact contract paths; link-check green across both (CI job covers both).
- Archive script: idempotent, immutable (existing `dl/<tag>/` untouched), verifies
  signatures/checksums before placing, generates the version index. Testable dry-run mode
  (no network in CI/sandbox — reason from source + a mocked-release fixture test if
  feasible).
- `install.yml`: Pages deploy job gone, lint/test jobs intact, workflow still valid.
- No `.rs` changes; full gate green.

### Starter prompt

```
/hort-architect

Implement backlog item 050 (issue #77) on branch agent/77-hort-rs-site. IMPORTANT: verify
`git branch --show-current` before every commit — never develop. Reuse the #78 site
pipeline (scripts/site/*, build-site.sh) and website ansible role — extend, don't fork.
Build the hort.rs static site (CLI landing + user docs from the four named md sources +
the apex installer scripts at their exact published paths), the /dl/ permanent archive
population script (immutable, cosign+checksum-verified before placing, backfills GitHub
release history, static version index, dry-run testable), parameterize the website role for
a second vhost + certbot domain, and retire install.yml's GitHub-Pages deploy job (keep its
lint/test jobs). Do NOT flip install-cli.sh's DL_BASE default (deliberate step 2, separate).
Full gate; report per the handover protocol.
```
