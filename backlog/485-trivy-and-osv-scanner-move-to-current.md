# 485 — Trivy and osv-scanner move to current, with their checksums and their fixtures

**Issue:** #463 · **Branch:** `agent/463-scanner-versions`.

## What to do

| pin | from | to |
|---|---|---|
| `docker/Dockerfile.worker` `ARG TRIVY_VERSION` | `0.70.0` | the current release |
| `docker/Dockerfile.worker` `ARG OSV_SCANNER_VERSION` | `2.3.8` | the current release |
| `deploy/ansible/roles/hort_systemd/defaults/main.yml` `hort_systemd_osv_version` | `2.3.8` | the same osv-scanner version, exactly |

As of 2026-11-26 the current releases were Trivy `0.76.2` and osv-scanner
`2.7.1`. **Re-read them at implementation time** rather than trusting those
numbers — if a newer one has appeared, take it and say which you took.

## What a version bump actually touches

**Four checksums, not two.** Each binary carries a SHA-256 per architecture
(`TRIVY_SHA256_AMD64`, `TRIVY_SHA256_ARM64`, `OSV_SCANNER_SHA256_AMD64`,
`OSV_SCANNER_SHA256_ARM64`). The build stages select by `TARGETARCH`, so a
missing or stale arm64 value breaks the multi-arch build and nothing before
that notices. The Dockerfile comments name the upstream files each value comes
from; take them from there, not from a mirror.

This is ADR 0006 at the call site: every external download is verified against
a checksum pinned where it is used. A bump that updates a version and leaves a
checksum behind turns a verified download into a build failure, which is the
safe direction — but it is still a broken build.

**The lockstep guard.** `scripts/check-osv-scanner-version.sh` asserts the
Dockerfile pin and the Ansible pin are **exactly** equal, because the native
deploy's binary must be the one the adapter was tested against — the v1 CLI has
no `scan source` subcommand, so drift there means every scan exits non-zero and
nothing ever earns release authority. Run the guard; do not reason about it.

**The revalidation, which is the substance — and two specific things it is
about.** "Check the fixtures" is too vague to be useful, so here is what
actually breaks.

**(i) The osv informational carve-out.**
`crates/hort-adapters-scanner-osv/tests/parse_fixtures.rs` holds a *real
osv-scanner 2.3.8 capture* for `proc-macro-error2` / RUSTSEC-2026-0173, whose
point is that `affected[].database_specific.informational == "unmaintained"`
routes onto the non-enforcing negligible lane. The comment states the
consequence of losing it: the advisory carries no CVSS score, so **without the
carve-out it hits the SUP-4 Critical fail-closed fallback and over-blocks.** If
2.x changed the shape or the location of that field, this is not a fixture
nit — it is a scanner that starts condemning unmaintained-advisory artifacts as
Critical. Re-capture against the new version and assert the lane, not the
string.

**(ii) The Trivy composition-equivalence measurement.**
`crates/hort-domain/src/oci.rs` records that against **Trivy 0.70.0 — named as
the version the Dockerfile pins** — an upper layer declaring `tar`, `tar+gzip`
or `tar+zstd` composed identically: same detected OS, same package inventory,
measured 2026-10-19 on hand-built two-layer layouts. That measurement is what
licenses ADR 0064 D1's position that hort's own decoder inventory does not
constrain the composed set. **A Trivy bump invalidates it**, and leaving the
comment as it stands would assert a measurement against a version we no longer
ship. Either re-measure it on the new version and update the date and version,
or state in the report that it was not re-measured and that the comment now
names a stale version — but do not silently leave it.

**If the new version reports differently, that is this unit's result and not an
obstacle.** Do not adjust a fixture until it matches the new output. Name each
divergence, say whether it is a new finding, a dropped finding, or a changed
shape, and leave the decision to the report. A quietly re-recorded fixture
destroys the only evidence that the scanner still detects what we believe it
detects.

## Acceptance

- Both binaries are at the version you name, with **all four** checksums
  updated from upstream, and a multi-arch build completes.
- `bash scripts/check-osv-scanner-version.sh` exits 0.
- The osv informational carve-out is revalidated against the new version and
  the test asserts the **negligible lane**, not a literal string.
- The Trivy composition-equivalence measurement is either re-measured (with the
  version and date updated) or reported as not re-measured, with the stale
  version named. Not left silently.
- Any other divergence in scanner output is named individually rather than
  absorbed into a re-recorded fixture.
- No consumer names a different Trivy version except the Ansible path, which
  deliberately names none (unit 486 covers the remaining consumer).
- The usual gate, with `cargo fmt` last.

## Not in scope

Pinning Ansible's Trivy. That path is deliberately rolling-latest — the apt
`generic` suite serves one version so a pin cannot hold, integrity comes from
the signed-by keyring, and latest is the right posture for a vulnerability
scanner. The defaults file argues it. Reversing that is its own decision.
