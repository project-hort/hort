# 048 — #78: project-hort.de — self-hosted static landing + operator docs (registry.hort.rs, ansible)

**Issue:** #78 (design settled with the maintainer — see the issue's pivot notes)
**Read first:** `README.md` (the #70 adopter landing — the content source for the landing page),
`docs/architecture/README.md` (nav), `docs/architecture/{how-to,reference,tutorial}/`,
`deploy/ansible/roles/nginx/` (`registry.hort.rs.conf.j2` is the vhost model),
`deploy/ansible/roles/certbot/`, `deploy/ansible/site-native.yml` (role wiring),
`install/index.html` (tone/posture reference).

## Design contract (settled — do not relitigate)

1. **Fully static.** The build produces a plain directory; nginx serves it. **Zero runtime
   dependency on hort-server** — the site must survive hort being down/redeployed.
2. **Single source of truth = this repo's markdown.** Landing content derives from the root
   `README.md`'s adopter material; docs pages are generated from `docs/architecture/`
   (operator scope: `how-to/` incl. `deploy/` + `operate/`, `reference/`, `tutorial/`).
   **No hand-authored second corpus** — a doc change here must reach the site on the next
   build with no manual copying. (Developer-facing `explanation/` + ADRs: out of this cut.)
3. **Dependency-light, pinned tooling.** No CDN assets on the pages (inline CSS; same
   supply-chain posture as `install/`). The generator must be a pinned, auditable choice —
   e.g. a pinned `pandoc` or a small committed script; NOT an npm-ecosystem SSG with a
   floating lockfile. Implementer's call within that guardrail.
4. **Deployment = ansible** (the operator runs it, like #74/#75): a vhost + content role;
   no GitHub Pages anywhere in this issue.

## Scope

### A. Site source + build (`site/` + `scripts/build-site.sh`)
- `site/` — templates/assets for the landing + docs chrome (header/nav/footer, inline CSS).
  The landing page: what hort is, the HORT pillars, main features (CAS, mandatory upstream
  verification, quarantine+scan fail-closed release, event-sourced audit trail, multi-format,
  sovereign self-hosting), quickstart pointer, links → GitHub repo, hort.rs (CLI), docs
  section. Claims must match the README — no overclaim (WASM modularization = roadmap).
- `scripts/build-site.sh` — builds the static tree into `site/dist/` (gitignored):
  landing + the docs section generated from `docs/architecture/`. **Inter-doc `.md` links
  must be rewritten to site paths** (the fiddly part — get `[x](../reference/y.md)` right);
  external links untouched. A link-check pass over the built output (internal anchors +
  relative paths) fails the build on breakage.
- CI: a small GitLab job (docs-change- and site-change-triggered) that runs the build +
  link-check so the site can't rot silently. Build output is NOT committed.

### B. Ansible role (`deploy/ansible/roles/website` or extending `nginx`)
- `project-hort.de` vhost modeled on `registry.hort.rs.conf.j2` (TLS via the existing
  certbot role — add the domain), serving the built directory (e.g.
  `/var/www/project-hort.de`).
- Content deploy: the role builds (or copies a prebuilt) `site/dist` onto the host. Choose
  the simplest robust mechanism: building on the operator machine at ansible-run time via
  `scripts/build-site.sh` + `synchronize`/`copy` is acceptable v1 (the operator checkout
  has the repo); document the choice in the role README.
- Security headers per the existing vhost's posture; no server-side execution — static only.
- DNS (`project-hort.de` → the host) + the ansible run are the operator's (documented in
  the role/README, not automated).

## Acceptance

- `scripts/build-site.sh` produces a self-contained `site/dist/`: landing + operator
  how-tos + reference + tutorial, all inter-doc links resolving (link-check green, in CI).
- No external/CDN asset anywhere in the output; no runtime dependency on hort-server.
- Ansible role renders a valid `project-hort.de` vhost (nginx config-test green in the
  role's check) + deploys the content; certbot domain added.
- Full gate green (`cargo test --workspace` etc. — no `.rs` expected, but run it).
- The README ↔ site claims stay consistent (spot-checkable, no divergent feature claims).

### Starter prompt

```
/hort-architect

Implement backlog item 048 (issue #78) on branch agent/78-project-hort-de-site. IMPORTANT:
verify `git branch --show-current` before every commit — never develop. Build the
project-hort.de static site: site/ chrome + scripts/build-site.sh generating landing (from
the root README's adopter content) + operator docs (from docs/architecture/ how-to,
reference, tutorial) with .md-link rewriting and a link-check that fails the build; a CI
job running build+link-check; and an ansible role (vhost modeled on registry.hort.rs.conf.j2,
certbot domain, static content deploy). Hard rules: fully static (zero hort-server runtime
dependency), single-source from the repo's md (no second corpus), dependency-light pinned
tooling (no CDN, no floating-lockfile SSG). Run the full gate; report per the handover
protocol, documenting your generator choice + content-deploy mechanism.
```
