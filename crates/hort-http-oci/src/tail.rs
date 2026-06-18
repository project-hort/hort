//! Wildcard-route tail parsing for OCI `/v2/:repo_key/*tail` requests.
//!
//! axum's matchit router can't distinguish `/v2/<name>/blobs/<digest>`
//! from `/v2/<name>/manifests/<ref>` or `/v2/<name>/tags/list` at the
//! route level (wildcards are terminal and can't be followed by literal
//! segments). This module does that disambiguation after the route
//! captures `*tail` as a single string, so the pull handlers can
//! dispatch on [`TailKind`] to the right serve function (blobs,
//! manifests, or tags list).
//!
//! Name segments themselves are allowed to contain slashes
//! (`library/nginx`), so parsing uses `rsplit_once` on the right-most
//! reserved keyword (`/blobs/`, `/manifests/`, `/tags/list`) to split
//! off the trailing segment(s). The OCI spec's name grammar reserves
//! these words and forbids them from appearing inside a legitimate
//! name, so the rightmost-match rule is unambiguous.

/// Parsed shape of the `*tail` capture following `/v2/:repo_key/`.
///
/// Borrowed from the original `tail` input so callers can pass slices
/// straight to serve functions without allocation.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TailKind<'a> {
    /// `<name>/blobs/<digest_str>`. `name` may itself be multi-segment
    /// (`library/nginx`). `digest_str` is raw — the blob serve
    /// function validates it.
    Blob { name: &'a str, digest_str: &'a str },
    /// `<name>/manifests/<reference>`. `reference` is raw and may be
    /// either a tag name (no `:`) or a digest (`sha256:<hex>`). The
    /// manifest serve function dispatches on the shape.
    Manifest { name: &'a str, reference: &'a str },
    /// `<name>/tags/list`. `name` may be multi-segment. The tags
    /// serve function drives the `RefUseCase::list` cursor walk and
    /// emits the OCI tags-list JSON envelope. OCI spec end-8.
    TagsList { name: &'a str },
    /// `<name>/referrers/<digest_str>`. `name` may itself be multi-
    /// segment. `digest_str` is raw — the referrers serve function
    /// validates it. OCI Distribution Spec v1.1 §referrers-api.
    Referrers { name: &'a str, digest_str: &'a str },
}

/// Extract the shape of an OCI pull request from the wildcard capture.
///
/// Ordering: blob before manifest. Both suffixes use `rsplit_once` so
/// a pathological name ending in a reserved word still splits on the
/// rightmost boundary. Tie goes to blobs — the ordering is deterministic
/// and none of the OCI reserved words nest inside one another.
pub(super) fn parse_tail(tail: &str) -> Option<TailKind<'_>> {
    if let Some((name, digest_str)) = tail.rsplit_once("/blobs/") {
        if name.is_empty() || digest_str.is_empty() {
            return None;
        }
        return Some(TailKind::Blob { name, digest_str });
    }
    if let Some((name, reference)) = tail.rsplit_once("/manifests/") {
        if name.is_empty() || reference.is_empty() {
            return None;
        }
        return Some(TailKind::Manifest { name, reference });
    }
    if let Some((name, digest_str)) = tail.rsplit_once("/referrers/") {
        if name.is_empty() || digest_str.is_empty() {
            return None;
        }
        return Some(TailKind::Referrers { name, digest_str });
    }
    // `<name>/tags/list` — terminal literal. Distinct from `/manifests/`
    // and `/blobs/` because the literal has no variable component after
    // the reserved word; use `strip_suffix` instead of `rsplit_once`.
    if let Some(name) = tail.strip_suffix("/tags/list") {
        if name.is_empty() {
            return None;
        }
        return Some(TailKind::TagsList { name });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_blob_single_segment_name() {
        assert_eq!(
            parse_tail("nginx/blobs/sha256:abc"),
            Some(TailKind::Blob {
                name: "nginx",
                digest_str: "sha256:abc",
            }),
        );
    }

    #[test]
    fn parse_blob_multi_segment_name() {
        assert_eq!(
            parse_tail("library/nginx/blobs/sha256:abc"),
            Some(TailKind::Blob {
                name: "library/nginx",
                digest_str: "sha256:abc",
            }),
        );
    }

    #[test]
    fn parse_manifest_by_tag() {
        assert_eq!(
            parse_tail("library/nginx/manifests/v1.2.3"),
            Some(TailKind::Manifest {
                name: "library/nginx",
                reference: "v1.2.3",
            }),
        );
    }

    #[test]
    fn parse_manifest_by_digest() {
        assert_eq!(
            parse_tail("library/nginx/manifests/sha256:abc"),
            Some(TailKind::Manifest {
                name: "library/nginx",
                reference: "sha256:abc",
            }),
        );
    }

    #[test]
    fn parse_tags_list_single_segment_name() {
        assert_eq!(
            parse_tail("nginx/tags/list"),
            Some(TailKind::TagsList { name: "nginx" }),
        );
    }

    #[test]
    fn parse_tags_list_multi_segment_name() {
        assert_eq!(
            parse_tail("library/nginx/tags/list"),
            Some(TailKind::TagsList {
                name: "library/nginx",
            }),
        );
    }

    #[test]
    fn parse_tags_list_empty_name_returns_none() {
        assert_eq!(parse_tail("/tags/list"), None);
    }

    #[test]
    fn parse_tags_list_partial_suffix_does_not_match() {
        // Suffix must be exact — `tags/list` with extra after, or
        // `tags/listing`, must not dispatch as TagsList.
        assert_eq!(parse_tail("nginx/tags/listing"), None);
        assert_eq!(parse_tail("nginx/tags/list/extra"), None);
    }

    #[test]
    fn parse_empty_name_blob_returns_none() {
        assert_eq!(parse_tail("/blobs/sha256:abc"), None);
    }

    #[test]
    fn parse_empty_digest_blob_returns_none() {
        assert_eq!(parse_tail("nginx/blobs/"), None);
    }

    #[test]
    fn parse_empty_name_manifest_returns_none() {
        assert_eq!(parse_tail("/manifests/latest"), None);
    }

    #[test]
    fn parse_empty_reference_manifest_returns_none() {
        assert_eq!(parse_tail("nginx/manifests/"), None);
    }

    #[test]
    fn parse_unknown_suffix_returns_none() {
        assert_eq!(parse_tail("nginx/wat/xyz"), None);
    }

    // -------------------- Referrers --------------------

    #[test]
    fn parse_referrers_single_segment_name() {
        assert_eq!(
            parse_tail("nginx/referrers/sha256:abc"),
            Some(TailKind::Referrers {
                name: "nginx",
                digest_str: "sha256:abc",
            }),
        );
    }

    #[test]
    fn parse_referrers_multi_segment_name() {
        assert_eq!(
            parse_tail("library/nginx/referrers/sha256:abc"),
            Some(TailKind::Referrers {
                name: "library/nginx",
                digest_str: "sha256:abc",
            }),
        );
    }

    #[test]
    fn parse_referrers_empty_name_returns_none() {
        assert_eq!(parse_tail("/referrers/sha256:abc"), None);
    }

    #[test]
    fn parse_referrers_empty_digest_returns_none() {
        assert_eq!(parse_tail("nginx/referrers/"), None);
    }
}
