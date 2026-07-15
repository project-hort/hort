# Licenses and third-party attribution

hort is dual-licensed **`MIT OR Apache-2.0`** (see `LICENSE-MIT` and
`LICENSE-APACHE`) — choose either. This page covers how to inspect what a binary
is licensed under and what it compiles in, and how a contributor keeps the
generated attribution in sync.

## See the license (operators)

Every binary prints its license and exits:

```bash
hort-server license          # -> MIT OR Apache-2.0 + pointers to the two files
hort-worker license --full   # also dumps both full license texts
hort-cli    license
```

These are print-and-exit commands — no config, no database, no server contact.

## See the compiled-in third-party components (operators / redistributors)

```bash
hort-cli attribution                 # human-readable list: each crate + version + URL + SPDX + license text
hort-cli attribution --format json   # machine-readable, for compliance tooling
```

The content is generated from the actual dependency graph and embedded into the
binary at build time, so it always matches what that binary ships. `attribution`
covers the **compiled-in Rust crates only**.

## Bundled external tools (a separate surface)

The container images bundle external tools that are *not* compiled into the Rust
binaries (e.g. `hort-worker` ships Trivy, osv-scanner, tini). Their attribution is
`docs/attribution/image-notice.md`, also `COPY`'d into each production image at
`/usr/share/hort/NOTICE`. This is deliberately separate from the `attribution`
command — do not conflate the two.

## Regenerate attribution after a dependency change (contributors)

The committed `THIRD-PARTY-LICENSES.md` and `.json` are generated from the
dependency graph with [`cargo-about`](https://github.com/EmbarkStudios/cargo-about)
(config `about.toml`). Any change that alters the graph (a `cargo update`, a new
dependency) must regenerate and commit them **in the same PR**:

```bash
cargo install cargo-about --locked --features cli   # once
scripts/regenerate-attribution.sh                    # rewrites both root artifacts
git add THIRD-PARTY-LICENSES.md THIRD-PARTY-LICENSES.json
```

CI enforces this: the `attribution-sync` job (GitLab `security:attribution-sync` /
GitHub `attribution-sync`) runs `scripts/check-attribution.sh`, which regenerates,
diffs against the committed files (stale → fail), and asserts `about.toml`'s
`accepted` license set equals `deny.toml`'s `[licenses] allow` — so no shipped
crate's license can be un-attributable. A new dependency whose license is outside
that allowlist is rejected earlier by `cargo deny check licenses`.

> Adding a license to the allowlist is a legal-review checkpoint: update **both**
> `deny.toml` `[licenses] allow` and `about.toml` `accepted` (the gate asserts
> parity), then regenerate.

For the licensing/attribution design and rationale see
[ADR 0047](../../adr/0047-dual-license-generated-attribution.md).
