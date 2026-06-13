# Verify a release with `cosign verify-blob`

This guide is for downstream consumers (operators, distro packagers, supply-chain
auditors) who want to verify the SBOM bundle and binary tarballs published with
each tagged release of `hort`.

Every release asset (`hort-sbom.tar.gz`, the per-target binary
tarballs, and the Windows `.exe`) ships with a sibling `.bundle` file — a
self-contained Sigstore bundle (signature + certificate + transparency-log
entry) produced by `cosign sign-blob` in the release pipeline. The signing
identity matches the keyless OIDC identity already used to sign the container
images (`docker-publish.yml`); there is no new key, no new secret, and no new
operator-facing knob.

## Prerequisites

- `cosign` ≥ v3.0 (Sigstore) on `PATH` — install via your distro, `brew install
  cosign`, or download the binary from
  <https://github.com/sigstore/cosign/releases>. (The release pipeline signs
  with the cosign v3 new-bundle format; verifying it needs a v3 client.)
- The release asset and its `.bundle` sibling, downloaded from
  <https://github.com/project-hort/hort/releases>.

## Verify the SBOM tarball

```sh
cosign verify-blob \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='https://github.com/project-hort/.*' \
  --bundle hort-sbom.tar.gz.bundle \
  hort-sbom.tar.gz
```

A `Verified OK` line on stdout means the signature was issued by the hort
release pipeline running on GitHub Actions. Any other output (or a non-zero exit
status) means the asset has been tampered with or did not come from the official
pipeline — do not unpack it.

## Verify a binary tarball

The same recipe applies to every per-target binary asset. For example:

```sh
cosign verify-blob \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp='https://github.com/project-hort/.*' \
  --bundle hort-cli-linux-amd64.tar.gz.bundle \
  hort-cli-linux-amd64.tar.gz
```

Each asset is named `hort-<component>-<os>-<arch>`. The `hort-cli` client ships
for `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64`, and
`windows-amd64` (the Windows asset is a `.exe` and uses the `.exe.bundle` sibling);
the `hort-server` and `hort-worker` daemons ship for `linux-amd64` and
`linux-arm64`. Substitute the asset name accordingly.

## Why two pipelines

GitHub Actions uses Sigstore Fulcio's **keyless OIDC** signing (the workflow's
`id-token: write` permission challenges Fulcio for an ephemeral certificate
bound to the workflow identity). The GitLab pipeline uses a Vault-pinned
long-lived **key** (`secret/data/platform/cosign/signing-key`) — same key the platform's
container images are signed with. The two pipelines differ in secret-management
surface by necessity. Downstream consumers fetching releases from
<https://github.com/project-hort/hort/releases> use the keyless
recipe above; consumers of internal GitLab releases verify against the
operator-published cosign public key (out of scope for this public guide).
