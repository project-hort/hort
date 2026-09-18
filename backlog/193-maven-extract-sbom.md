# 193 — Maven `extract_sbom` for `.pom` and `.jar` (META-INF/maven) — `osv` becomes effective on Maven

**Issue:** #265 · **Branch:** `agent/265-maven-extract-sbom` · single item.

## Governing decisions

None new. Precedent: `crates/hort-formats/src/pypi.rs::extract_sbom` (subject from coordinates,
components from declared dependencies, purl convention, `Some(Sbom{subject, components: []})` for
a leaf); the Maven handler already owns the POM reader (`maven/pom.rs::parse_pom_dependencies`:
compile/runtime scope, concrete versions, `PomSkip` with reason) and the coordinates
(`maven/coords.rs`); `Ecosystem::Maven` exists (`hort-domain/src/types/sbom.rs`) and the OSV
adapter maps it to purl type `maven` (`osv/ecosystem.rs`).

## The gap

`FormatHandler::extract_sbom` defaults to `Ok(None)`; Maven inherits it, so `OsvScanner::scan`
logs "scan skipped — no SBOM provided" and `scan_backends: ["osv"]` on a Maven repository scans
nothing (#259's finding).

## Change

1. `MavenFormatHandler::extract_sbom(coords, format_metadata, payload)`:
   - **Subject**: `pkg:maven/{groupId}/{artifactId}@{version}` from `coords`, `Ecosystem::Maven`
     (mirror `build_subject_component`).
   - **`.pom` payload**: the payload is the POM → `parse_pom_dependencies` → one `SbomComponent`
     per resolved `DependencySpec` (`purl: pkg:maven/g/a@v`, `name: "g:a"`, `version`,
     `Ecosystem::Maven`, `licenses: []`, `direct_dependency: true`). `PomSkip` entries yield no
     component (no purl without a version); their per-reason counts go to the existing
     `info!` line, not into the SBOM.
   - **`.jar` / `.war` payload**: read `META-INF/maven/{g}/{a}/pom.xml` from the zip (bounded by
     the existing payload cap; reject entries with traversal in the name) and treat it as the
     POM; absent → `Some(Sbom{subject, components: []})` — the leaf case, which still lets OSV
     query the artifact's own coordinate.
   - Everything else under the Maven layout (`.sha1`/`.md5`/`.asc`, `maven-metadata.xml`,
     sources/javadoc classifiers): `Ok(None)` as today.
2. No schema, no policy change, no new knob.

## Tests (hort-formats ≥ 85 % on the new code; no DB)

- `.pom` with three dependencies (compile, runtime, one resolved through `<dependencyManagement>`)
  ⇒ three components with exact purls; subject from the coordinates.
- `.pom` with a property placeholder / a version range ⇒ that dependency omitted, subject present.
- `.jar` with `META-INF/maven/…/pom.xml` ⇒ same as the `.pom` case; `.jar` without ⇒ subject
  only; a traversal-named zip entry ⇒ ignored, no panic.
- `.sha1` / `maven-metadata.xml` ⇒ `None`.
- OSV adapter round-trip: `Ecosystem::Maven` ↔ `pkg:maven/` (extend the existing ecosystem test if
  the mapping is not already pinned).
- **E2E** (mirror dogfood (h) on `hort-crates`): a Maven repository with `scanBackends: ["osv"]`,
  `enforcement: record`, a `.pom` declaring a known-affected coordinate (e.g.
  `org.apache.logging.log4j:log4j-core:2.14.1`) ⇒ `ScanCompleted` with ≥ 1 finding attributed to
  `osv`. Branch-first on the human's harness; MR only after green.

## Acceptance

- `osv` yields real findings on a Maven repository (the E2E above, green).
- No change to the npm/cargo/pypi extractors.
- #259's map can carry `maven × osv` as an evidenced "yes" cell.
- Gate: fmt, clippy, `cargo test --workspace`, audit, deny. `CHANGELOG.md` `### Fixed`: OSV scanning
  now covers Maven artifacts (POM-declared dependencies, JARs via their embedded POM).
