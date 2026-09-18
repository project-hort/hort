# 202 — Trivy scan mode per artifact kind follows Trivy's coverage matrix (post-build kinds via `rootfs`)

**Issue:** #264 · **Branch:** `agent/264-trivy-materialisation` (continues item 191) · single item · adapter + docs.

## Defect (measured on the compose E2E, worker built from `61be2318`)

`quarantine/trivy-jar-finding` step (3): the JAR was materialised as `log4j-core-2.14.1.jar` and
scanned with `trivy fs` → `report carries no analysed target; no verdict` → `scan_indeterminate`.
The `.pom` of the same coordinate, scanned with `trivy fs` as `pom.xml`, was analysed (1 target,
8 findings). Trivy's coverage matrix (https://trivy.dev/docs/latest/coverage/language/, the
authority here) explains both: **post-build** artifacts — `JAR/WAR/PAR/EAR`, Python `egg`/`wheel`
packages, Node `package.json` (under `node_modules`), Go/cargo-auditable binaries — are analysed
by the **Image and Rootfs** targets only; **pre-build** files — `pom.xml`, `package-lock.json`,
`requirements.txt`/`poetry.lock`/`uv.lock`, `gradle.lockfile` — by **Filesystem and Repository**
only; `Cargo.lock` by all four. Item 191's table (`workspace.rs` module doc, rows 16–22) assigns
`fs` to every non-OCI kind, so every post-build kind can never produce a verdict.

## Change

1. **Mode per kind, from the matrix** (`workspace.rs` plan table + `Plan`/`ScanMode` selection):

   | kind | materialisation | mode |
   |---|---|---|
   | `MavenJar` | single file keeping its `.jar`/`.war`/`.ear`/`.par` name | **`rootfs`** |
   | `MavenPom` | `pom.xml` | `fs` (unchanged) |
   | `PyWheel` | ZIP extracted (contains `<dist>-<ver>.dist-info/METADATA`) | **`rootfs`** |
   | `PySdist` | tar extracted (`*.egg-info/PKG-INFO` when setuptools emitted it) | **`rootfs`** |
   | `NpmTarball` | extracted so the package lands at `node_modules/<name>/package.json` (Trivy only reads `package.json` under `node_modules`; `<name>` from the coords, scoped names keep their `@scope/` directory) | **`rootfs`** |
   | `CargoCrate` | extracted (`Cargo.toml` + `Cargo.lock` when the crate ships one) | `fs` (unchanged; a library crate without `Cargo.lock` yields no target → `NothingAnalysable`, which is the honest verdict) |
   | `OciBlob` | tar layer as root filesystem | `rootfs` (unchanged) |

   The module doc table gets a "why this mode" column citing the matrix, and the docs page for
   the Trivy backend (`git grep -ln "trivy" docs/architecture/reference docs/metrics-catalog.md`)
   the same table.
2. **Empty-report diagnostics.** The `warn!` "report carries no analysed target; no verdict" also
   carries Trivy's stderr tail (last ~1 KiB of the capped buffer, `stderr_tail` field) and the
   workspace listing (`materialised = <relative file names, capped at 20>`): the E2E showed the
   warning is unactionable without them. `--quiet` stays.
3. **Java DB.** Trivy downloads `trivy-java-db` "when any JAR file is found" and pom.properties/
   MANIFEST are insufficient; log4j-core carries `pom.properties`, so no download is needed for
   the E2E, but the worker's cache dir (`HORT_SCANNER_TRIVY_DB_DIR` → `--cache-dir`) must be
   writable for the case that needs it. No new knob; document the behaviour in the backend docs
   page and state in the report whether the E2E log shows a Java DB fetch.
4. **Rebase first**: the branch predates the `create_policy` enforcement fix on `develop`
   (the E2E log shows `enforcement=reject` for a policy declared `record`); rebase onto
   `origin/develop` before the change, resolving `CHANGELOG.md` by keeping each bullet under its
   own heading.
5. Tests: `scan_argv` per kind pins the subcommand (`rootfs` for the post-build kinds, `fs` for
   pom/cargo); a materialisation test for `NpmTarball` asserts the `node_modules/<name>/` layout
   (scoped and unscoped); the `TRIVY_BIN`-gated evidence tests switch the JAR case to `rootfs`.

## Acceptance

- `quarantine/trivy-jar-finding` green on the human's harness with the worker log showing
  `trivy adapter: scan completed … kind=maven_jar subcommand=rootfs analysed_targets=1` and ≥ 1
  finding for CVE-2021-44228; the `.pom` control still analysed under `fs`.
- Unit tests above green; gate green (fmt, clippy, `cargo test --workspace`, audit, deny).
- Docs table and module doc match the matrix; no issue numbers in code comments.
