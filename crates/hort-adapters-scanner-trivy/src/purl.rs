//! PURL constructor for Trivy findings — pure function, no I/O.
//!
//! The Trivy `Type` field on a `TrivyResult` identifies the package
//! source (alpine, debian, ubuntu, npm, pypi, cargo, go-binary, jar,
//! maven, nuget, gem, etc.). Each Trivy type maps to the PURL spec's
//! `pkg:<type>` namespace per
//! <https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst>.
//!
//! A few Trivy types collapse into a single PURL type (e.g. all RPM
//! distros become `pkg:rpm/...`). Unknown types fall through to
//! `pkg:generic/...` — the orchestrator can still correlate findings
//! by `(purl, vulnerability_id)`, just with reduced cross-source
//! deduplication coverage.

/// Map a Trivy `Type` field to its PURL `pkg:<type>` namespace. The
/// returned identifier is the PURL type, not a `pkg:` prefix.
pub(crate) fn trivy_type_to_purl_type(trivy_type: &str) -> &'static str {
    match trivy_type {
        "alpine" => "apk",
        "debian" | "ubuntu" => "deb",
        "rocky" | "centos" | "redhat" | "amazon" | "oraclelinux" | "rpm" => "rpm",
        "npm" => "npm",
        "pypi" | "pip" => "pypi",
        "cargo" | "rust" => "cargo",
        "gomod" | "go-binary" => "golang",
        "jar" | "maven" => "maven",
        "nuget" => "nuget",
        "bundler" | "gemspec" => "gem",
        _ => "generic",
    }
}

/// Construct a PURL string from a Trivy `(Type, PkgName, InstalledVersion)`
/// triple.
///
/// Maven names ship as `groupId:artifactId`; the function splits on the
/// first colon and emits `pkg:maven/groupId/artifactId@version`. Other
/// PURL types use the bare name segment. The version is always appended
/// after `@`.
pub(crate) fn build_purl(trivy_type: &str, pkg_name: &str, installed_version: &str) -> String {
    let purl_type = trivy_type_to_purl_type(trivy_type);
    if purl_type == "maven" {
        if let Some((group, artifact)) = pkg_name.split_once(':') {
            return format!("pkg:maven/{group}/{artifact}@{installed_version}");
        }
        // Fall through to the generic encoding when the Maven name
        // doesn't carry the expected `groupId:artifactId` shape — the
        // PURL is still well-formed, just less faithful.
    }
    format!("pkg:{purl_type}/{pkg_name}@{installed_version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- trivy_type_to_purl_type ------------------------------------------

    #[test]
    fn alpine_maps_to_apk() {
        assert_eq!(trivy_type_to_purl_type("alpine"), "apk");
    }

    #[test]
    fn debian_and_ubuntu_map_to_deb() {
        assert_eq!(trivy_type_to_purl_type("debian"), "deb");
        assert_eq!(trivy_type_to_purl_type("ubuntu"), "deb");
    }

    #[test]
    fn rpm_family_maps_to_rpm() {
        for t in ["rocky", "centos", "redhat", "amazon", "oraclelinux", "rpm"] {
            assert_eq!(trivy_type_to_purl_type(t), "rpm", "type {t}");
        }
    }

    #[test]
    fn npm_maps_to_npm() {
        assert_eq!(trivy_type_to_purl_type("npm"), "npm");
    }

    #[test]
    fn pypi_aliases_map_to_pypi() {
        assert_eq!(trivy_type_to_purl_type("pypi"), "pypi");
        assert_eq!(trivy_type_to_purl_type("pip"), "pypi");
    }

    #[test]
    fn cargo_aliases_map_to_cargo() {
        assert_eq!(trivy_type_to_purl_type("cargo"), "cargo");
        assert_eq!(trivy_type_to_purl_type("rust"), "cargo");
    }

    #[test]
    fn go_aliases_map_to_golang() {
        assert_eq!(trivy_type_to_purl_type("gomod"), "golang");
        assert_eq!(trivy_type_to_purl_type("go-binary"), "golang");
    }

    #[test]
    fn jar_and_maven_map_to_maven() {
        assert_eq!(trivy_type_to_purl_type("jar"), "maven");
        assert_eq!(trivy_type_to_purl_type("maven"), "maven");
    }

    #[test]
    fn nuget_maps_to_nuget() {
        assert_eq!(trivy_type_to_purl_type("nuget"), "nuget");
    }

    #[test]
    fn bundler_and_gemspec_map_to_gem() {
        assert_eq!(trivy_type_to_purl_type("bundler"), "gem");
        assert_eq!(trivy_type_to_purl_type("gemspec"), "gem");
    }

    #[test]
    fn unknown_type_maps_to_generic() {
        assert_eq!(trivy_type_to_purl_type("exotic-format"), "generic");
        assert_eq!(trivy_type_to_purl_type(""), "generic");
    }

    // ----- build_purl --------------------------------------------------------

    #[test]
    fn npm_lodash_builds_canonical_purl() {
        assert_eq!(
            build_purl("npm", "lodash", "4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn maven_groupid_artifactid_splits_on_colon() {
        assert_eq!(
            build_purl("maven", "com.example:foo", "1.2.3"),
            "pkg:maven/com.example/foo@1.2.3"
        );
    }

    #[test]
    fn jar_alias_also_splits_groupid_artifactid() {
        // `jar` collapses to maven via trivy_type_to_purl_type — the
        // colon-split kicks in for jar findings too.
        assert_eq!(
            build_purl("jar", "org.springframework:spring-core", "5.3.27"),
            "pkg:maven/org.springframework/spring-core@5.3.27"
        );
    }

    #[test]
    fn maven_without_colon_falls_through_to_generic_encoding() {
        // Anomalous Trivy output: a maven entry with a bare name
        // (no groupId:artifactId). PURL is still produced — slightly
        // less faithful but well-formed.
        assert_eq!(
            build_purl("maven", "spring-core", "5.3.27"),
            "pkg:maven/spring-core@5.3.27"
        );
    }

    #[test]
    fn alpine_busybox_uses_apk_purl_type() {
        assert_eq!(
            build_purl("alpine", "busybox", "1.36"),
            "pkg:apk/busybox@1.36"
        );
    }

    #[test]
    fn go_binary_module_path_passes_through() {
        // Go module paths embed slashes; PURL accepts them in the name
        // segment for `pkg:golang`. We don't try to canonicalise.
        assert_eq!(
            build_purl("go-binary", "github.com/foo/bar", "v1.0.0"),
            "pkg:golang/github.com/foo/bar@v1.0.0"
        );
    }

    #[test]
    fn pypi_requests_uses_pypi_purl_type() {
        assert_eq!(
            build_purl("pypi", "requests", "2.28.0"),
            "pkg:pypi/requests@2.28.0"
        );
    }

    #[test]
    fn rpm_family_uses_rpm_purl_type() {
        assert_eq!(
            build_purl("redhat", "openssl-libs", "1.1.1k-7.el8_6"),
            "pkg:rpm/openssl-libs@1.1.1k-7.el8_6"
        );
    }

    #[test]
    fn unknown_trivy_type_uses_generic_purl_type() {
        assert_eq!(
            build_purl("brand-new-format", "foo", "1.0"),
            "pkg:generic/foo@1.0"
        );
    }
}
