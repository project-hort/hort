# 487 — something proposes the next scanner bump

**Issue:** #463 · **Branch:** `agent/463-scanner-versions`. **After units 485
and 486**, so the mechanism is written against pins that are already current.

## Why this unit exists

The two scanner pins fell six and four minor versions behind, and the reason is
structural rather than inattention: **nothing watches them.** The `ARG` pins in
`docker/Dockerfile.worker` carry no Renovate annotation, and `renovate.json`
disables the `github-actions` manager because Dependabot owns
`.github/workflows`. A comment cannot hold this invariant; a manager can.

## What to do

Add `customManagers` entries to `renovate.json` for `ARG TRIVY_VERSION` and
`ARG OSV_SCANNER_VERSION`, with `datasource=github-releases` against the
upstream repositories.

**And then answer the question that decides whether this is useful**: can the
four SHA-256 checksums travel with the version bump? If they cannot, a Renovate
MR arrives with a new version and stale checksums, the verified download fails,
and the MR can never go green — a mechanism that reliably produces red MRs is
worse than none, because it trains everyone to ignore it.

Two honest outcomes, and the unit picks one with its reasoning:

- **The checksums can be covered** — by a `customManager` that also updates
  them, or by a build that derives them from an upstream `SHA256SUMS` the
  bump makes available, as long as ADR 0006 still holds: the value is pinned
  where it is used, not fetched at build time without a pin.
- **They cannot** — then say so plainly, and make the mechanism's output
  something a human finishes: a Renovate MR that bumps the version and a
  statement in the dashboard entry that the checksums must be updated before
  it can merge. That is still better than silence, but it must be stated so
  nobody mistakes a red MR for a broken pipeline.

Also decide what happens to the workflow pins while `github-actions` stays
disabled: either they are covered another way, or the unit records that they
depend on Dependabot and names the file that configures it.

## Acceptance

- A mechanism exists that **proposes** a bump for both `ARG` pins, demonstrated
  rather than asserted — a dry run, a config validation, or the first MR it
  produces.
- The checksum question is answered in the report with the reasoning, not left
  open.
- `renovate.json` stays valid; the existing disabled-manager decision and its
  comment survive, including the note that Renovate reads the config from the
  default branch so the change takes effect only after a promotion to `main`.

## Not in scope

Enabling the `github-actions` manager, or changing the division of labour
between Renovate and Dependabot. Both are standing decisions with their reason
recorded in `renovate.json`.

## Resolved 2026-11-26

**The checksums cannot travel.** `github-releases` yields a release version;
the four `*_SHA256_{AMD64,ARM64}` ARGs are the contents of a separate per-arch
asset in that release, and a regex manager has no mapping from the tag to
those contents. Fetching the checksum file at build time and trusting it
would make the pin a restatement of whatever the download said, which is the
shape ADR 0006 rejects one layer down for proxied artifacts; here the
governing contract is the Dockerfile's own, that the expected digest is
committed beside the version it belongs to. So the mechanism proposes a
version and a human completes the pair — the second of the two outcomes
above.

**But the hazard this unit was written to avoid is the wrong way round.** The
premise above — "the verified download fails and the MR can never go green" —
is false: `build-images:hort-worker` runs on `v*` tags, `main` and `release/*`
only, so nothing in a merge-request pipeline builds the worker image. A
version-only bump is **green**, and `sha256sum -c` refuses it at the next
release tag, after the merge. The failure is still fail-closed and loud — a
stale checksum can never admit an unverified binary — but it is paid for one
step later than assumed, by a burned tag rather than a red MR. The dashboard
header and `prBodyNotes` therefore say exactly that, because "update the
checksums before merging" reads as *CI will stop you* and nothing will.

**A fourth Trivy statement and a third osv-scanner one existed.**
`docs/attribution/image-notice.md` named Trivy 0.70.0 and osv-scanner 2.3.8
after unit 485 shipped 0.76.2 and 2.7.1 — a published NOTICE describing an
image that no longer existed. The file asks for its own update in its own
prose, which is why it drifted: unit 485's pin table listed the two places
that *install* a scanner and no place that merely *states* its version. Both
pin-sync guards now read the NOTICE as a site (four-way for Trivy, three-way
for osv-scanner), both custom managers update it, and
`.code-changed-paths` gained it plus
`deploy/ansible/roles/hort_systemd/defaults/main.yml`, which the osv guard has
always read while an edit to it alone skipped the gate.

**Two stale claims removed.** Both workflow install steps asserted that the
`aquasecurity/trivy` GitHub repository "was wiped (no releases/tags)" — which
the Dockerfile has contradicted all along by downloading release tarballs from
it, and which `github-releases` as a datasource contradicts again. The comments
now state why the install uses the published image, without the false premise.

**The config form was checked against the runner, not against the newest
Renovate.** `dependencyDashboard` became an object on 2026-11-11 (Renovate
44.238.x); the flat `dependencyDashboardHeader` is still migrated forward. The
nested form is only safe if the deployed runner is newer than that, and an
unknown or wrong-typed option is a repository-level config error — Renovate
skips the repository, which would silence every proposal including the cargo
flow, and the fix would have to reach `main` to take effect. The runner's
version is in the `renovate-debug` blob of any Renovate MR body: **44.263.5**,
released the evening before it ran. The nested form is correct here.
