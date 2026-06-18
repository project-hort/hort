# install/ — hort-cli installer source

## Single source of truth

This directory is the authoritative source for the installer scripts and pinned
data served at **https://hort.rs**. Files authored and tested here are published
to the **main repo's own GitHub Pages site (`hort.rs`)** by CI on merge to
`main` — the installer lives alongside the binaries and signing config it
depends on. There is no separate installer repo; all changes flow from here.
At go-live, `hort.rs` serves `install-cli.sh`, `install-cli.ps1`, `cosign.pin`,
and the landing page (`index.html`) as static files from this directory.

## Files

| File | Purpose |
|---|---|
| `cosign.pin` | Pinned cosign version + SHA-256 digests for the installer bootstrap |
| `install-cli.sh` | POSIX shell installer (Linux, macOS) |
| `install-cli.ps1` | PowerShell installer (Windows) |

## Cosign bump procedure

The installer bootstraps cosign before verifying hort-cli release artifacts.
**cosign must remain >= v3.0** — the hort release pipeline signs with the cosign
v3 new-bundle format; a v2 client cannot verify.

To bump to a new cosign release:

```sh
# 1. Find the latest release tag (must be >= v3.0)
curl -fsSL https://api.github.com/repos/sigstore/cosign/releases/latest \
  | grep '"tag_name"'

# 2. Download the checksum file
CV=<new-tag>   # e.g. v3.2.0
curl -fsSL \
  "https://github.com/sigstore/cosign/releases/download/${CV}/cosign_checksums.txt" \
  -o /tmp/cosign_checksums.txt

# 3. Extract the five required hashes
grep -E \
  'cosign-(linux|darwin)-(amd64|arm64)$|cosign-windows-amd64\.exe$' \
  /tmp/cosign_checksums.txt

# 4. Update install/cosign.pin with the new version and hashes
#    (COSIGN_VERSION and all five COSIGN_SHA256_* keys)

# 5. Sanity-check the file parses
sh -c '. ./install/cosign.pin; echo "$COSIGN_VERSION $COSIGN_SHA256_linux_amd64"'
# Expected output: <CV> <64-char hex hash>

# 6. Commit
git add install/cosign.pin
git commit -m "chore(installer): bump cosign to ${CV}"
```

## Verify parameters

The installer scripts verify hort-cli release artifacts using:

| Parameter | Value |
|---|---|
| Identity regexp | `https://github.com/project-hort/.*` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |
| Cosign minimum version | v3.0 |

These values **must stay in sync** with
`docs/architecture/how-to/release-verification.md`. The consistency test
`install/tests/test_pin_consistency.sh` enforces this on every CI run.
