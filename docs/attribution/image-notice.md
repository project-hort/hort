# Image-Level NOTICE — Bundled External Tools

This document is the attribution NOTICE for **external, non-Rust tools and base
image contents bundled into hort's production container images**. It is a
separate surface from `THIRD-PARTY-LICENSES.md` / `THIRD-PARTY-LICENSES.json`
(the Rust crate dependency graph compiled into `hort-server` / `hort-worker` /
`hort-cli`, embedded in those binaries and surfaced via the `attribution`
subcommand — see `crates/hort-attribution`). Nothing here is generated or
embedded at compile time; this is a hand-maintained doc kept in sync with the
`docker/Dockerfile.*` pins it describes.

Do not conflate the two: a Rust crate change regenerates
`THIRD-PARTY-LICENSES.{md,json}` (`scripts/regenerate-attribution.sh`); a
bundled-tool version bump in a Dockerfile updates this file by hand.

## `hort-worker` (`docker/Dockerfile.worker`)

| Tool | Version | Upstream project | License (SPDX) |
| --- | --- | --- | --- |
| Trivy | 0.70.0 | https://github.com/aquasecurity/trivy | Apache-2.0 |
| osv-scanner | 2.3.8 | https://github.com/google/osv-scanner | Apache-2.0 |
| tini | as pinned by `debian:trixie-slim`'s `tini` package (installed via `apt-get install tini`, no separate upstream version pin — see the Dockerfile's Stage 4 comment) | https://github.com/krallin/tini | MIT |

Versions above are pinned by the `TRIVY_VERSION` / `OSV_SCANNER_VERSION` build
`ARG`s (and their paired `*_SHA256_*` checksum `ARG`s) at the top of
`docker/Dockerfile.worker`. When those `ARG`s are bumped, update the version
column here in the same change.

### Base image contents (`hort-worker` runtime stage)

The runtime stage is `gcr.io/distroless/cc-debian13:nonroot`, digest-pinned in
`docker/Dockerfile.worker` (see the `FROM gcr.io/distroless/cc-debian13:nonroot@sha256:…`
line). The distroless project itself
(https://github.com/GoogleContainerTools/distroless) is Apache-2.0. It bundles
a minimal set of Debian trixie (13) runtime packages with their own upstream
licenses:

| Component | Upstream project | License (SPDX) |
| --- | --- | --- |
| glibc (GNU C Library) | https://www.gnu.org/software/libc/ | LGPL-2.1-or-later |
| libgcc1 (GCC support runtime) | https://gcc.gnu.org/ | GPL-3.0-or-later WITH GCC-exception-3.1 |
| ca-certificates (Mozilla CA bundle, Debian packaging) | https://packages.debian.org/trixie/ca-certificates | MPL-2.0 |

The intermediate build stages (`trivy`, `osv`, `tini`; all `debian:trixie-slim`)
do not ship in the final image — only the binaries `COPY`'d from them do — so
their own package contents (curl, ca-certificates used transiently to fetch
and verify the pinned tarballs) are not part of the runtime image's third-party
surface and are omitted here.

## `hort-server` (`docker/Dockerfile.hort-server`)

`hort-server` ships no bundled external tools — only two first-party binaries,
`hort-server` and `hort-cli` (both covered by the `attribution` subcommand, not
this NOTICE). Its only third-party surface is the same distroless base image
as `hort-worker`:

### Base image contents (`hort-server` runtime stage)

The runtime stage is `gcr.io/distroless/cc-debian13:nonroot`, digest-pinned in
`docker/Dockerfile.hort-server`. Same base as `hort-worker` above:

| Component | Upstream project | License (SPDX) |
| --- | --- | --- |
| glibc (GNU C Library) | https://www.gnu.org/software/libc/ | LGPL-2.1-or-later |
| libgcc1 (GCC support runtime) | https://gcc.gnu.org/ | GPL-3.0-or-later WITH GCC-exception-3.1 |
| ca-certificates (Mozilla CA bundle, Debian packaging) | https://packages.debian.org/trixie/ca-certificates | MPL-2.0 |

## Deferred: client / E2E test image

`scripts/native-tests/Dockerfile.client` bundles a much larger set of external
tools (skopeo, Node.js/npm, Maven, Gradle, cosign, OpenJDK, rustup, and more).
That image is a **dev/E2E test harness, never published or shipped to
operators** (per design doc `docs/plans/dual-license-attribution.md` §8) — it
is explicitly **deferred as a follow-on** and is out of scope for this NOTICE.
If it is ever covered, it gets its own client-image NOTICE rather than being
folded into this one.
