# install/ — hort-cli installer source

## Single source of truth

This directory is the authoritative source for the installer scripts and pinned
data served at **https://hort.rs**. There is no separate installer repo; all
changes flow from here.

`install-cli.sh`, `install-cli.ps1`, and `cosign.pin` are copied byte-for-byte
into the generated hort.rs site at their exact published apex paths by
`scripts/build-site.sh --site hort.rs` (see
`scripts/site/generate.py::copy_hort_rs_apex_files`), deployed by the
`website` ansible role (`deploy/ansible/roles/website/`,
`deploy/ansible/site-website.yml`) — **not** GitHub Pages (that path was
retired in issue #77; `.github/workflows/install.yml` still lints and
fixture-tests these scripts on every push/PR, it just no longer deploys
them). `index.html` here predates that pipeline and is not currently served —
hort.rs's actual landing page is generated from
`docs/architecture/how-to/install-cli.md` by the same build (see
`scripts/site/generate.py::build_hort_rs_landing`); this file is kept as a
design/tone reference pending an explicit decision to delete it.

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

## Internal CI-test knob

`_HORT_INTERNAL_TEST_BAD_IDENTITY` (leading underscore = internal-only naming
convention; INFRA-15) is a **CI-test-only** environment variable read by
`install-cli.sh` / `install-cli.ps1`. When set to `1` it substitutes a
deliberately *non-matching* cosign `--certificate-identity-regexp`
(`https://github.com/definitely-not-project-hort/.*`) so a test can assert the
installer's signature verification **fails closed** on an identity mismatch.

It is **fail-closed and not operator-facing**: it can only make verification
*stricter* (force a reject), never weaker — it cannot skip or relax the shipped
`https://github.com/project-hort/.*` identity gate. Do not set it in a real
install.
