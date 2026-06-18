# Install `hort-cli`

The Hort command-line client installs with a single command on Linux, macOS, and Windows.

## Linux / macOS

```sh
curl -fsSL https://hort.rs/install-cli.sh | sh
```

## Windows (PowerShell)

```powershell
irm https://hort.rs/install-cli.ps1 | iex
```

## What the installer guarantees

It is **fail-closed**: before anything is written to your system it

1. verifies the download's **SHA-256** against the published checksum, and
2. verifies the download's keyless [**cosign**](https://docs.sigstore.dev/) signature
   against the Hort release identity (`cosign verify-blob`).

If either check fails, nothing is installed. If `cosign` isn't already on your `PATH`,
the installer bootstraps a version-pinned copy (cosign ≥ v3.0) and verifies *its* checksum
before using it. There is intentionally no option to skip verification.

To verify a download yourself instead, see [release-verification.md](./release-verification.md).

## Options

| Flag (sh) | Flag (PowerShell) | Environment | Default |
|---|---|---|---|
| `--version vX.Y.Z` | `-Version vX.Y.Z` | `HORT_VERSION` | latest release (prerelease-aware until 1.0) |
| `--dir <path>` | `-Dir <path>` | `HORT_INSTALL_DIR` | `~/.local/bin` (Unix), `%LOCALAPPDATA%\Programs\hort\bin` (Windows) |
| `--add-to-path` | `-AddToPath` | — | off (prints the line to add to `PATH`) |
| `--help` | — | — | — |

Set `GITHUB_TOKEN` to avoid GitHub API rate limits when resolving the latest version.

Pin a specific version:

```sh
HORT_VERSION=v1.0.0 curl -fsSL https://hort.rs/install-cli.sh | sh
```

## Versions

`--version` / `HORT_VERSION` installs any released version; the default is the latest
(prerelease-aware until a stable 1.0). To run two versions side by side, install them to
different directories with `--dir`. **Pin `--version` to match your hort-server** when you
need a specific client — the CLI↔server compatibility window is defined per release (policy
TBD pre-1.0; the installer itself enforces no compatibility, it only places a verified binary).

## Upgrade / uninstall

Re-run the one-liner to upgrade (it replaces the binary in place; pass `--version` to
pin or downgrade). To uninstall, delete `hort-cli` from your install directory — it is a
single static binary.
