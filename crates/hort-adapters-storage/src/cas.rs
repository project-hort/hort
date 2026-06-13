use hort_domain::types::ContentHash;

/// Derive the storage path from a content hash.
///
/// Format: `cas/{hash[0..2]}/{hash[2..4]}/{hash}`
///
/// Two-level directory sharding prevents any single directory from accumulating
/// too many entries. Internal to the adapter — the domain layer never sees
/// storage paths.
pub(crate) fn cas_path(hash: &ContentHash) -> String {
    let h: &str = hash.as_ref();
    format!("cas/{}/{}/{}", &h[0..2], &h[2..4], h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of empty input.
    #[test]
    fn cas_path_empty_content_hash() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        assert_eq!(
            cas_path(&hash),
            "cas/e3/b0/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// SHA-256 of b"hello world".
    #[test]
    fn cas_path_hello_world_hash() {
        let hash: ContentHash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            .parse()
            .unwrap();
        assert_eq!(
            cas_path(&hash),
            "cas/b9/4d/b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    /// Verify sharding uses first two and next two hex characters.
    #[test]
    fn cas_path_sharding_structure() {
        let hash: ContentHash = "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
            .parse()
            .unwrap();
        let path = cas_path(&hash);
        assert!(path.starts_with("cas/aa/bb/"));
        assert!(path.ends_with(hash.as_ref()));
    }
}
