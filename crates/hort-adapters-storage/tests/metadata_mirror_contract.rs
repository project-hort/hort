//! Two invariants of the raw-upstream-metadata mirror port, asserted
//! against both production backends through the trait.
//!
//! ## 1. A temp path is not a key, and not another key's temp path
//!
//! The filesystem backend writes through a temp file and renames. The
//! temp name used to be `path.with_extension("tmp")`, and
//! `Path::with_extension` **replaces** an existing extension rather than
//! appending one, which made two distinct consequences:
//!
//! - two keys differing only in their extension shared **one** temp
//!   path, so concurrent writes interleaved into the same file and the
//!   rename could move one key's half-written body onto the other key's
//!   path;
//! - the temp path was itself a perfectly valid key — `resolve` maps any
//!   key onto `<root>/<key>` — so a `get` could serve a half-written
//!   body during the write, or an orphan forever after a crash.
//!
//! The close is a reserved, non-addressable subtree with a unique name
//! per write, and a key validator that refuses to resolve into it.
//!
//! ## 2. A mirror body carries its own digest, and a read verifies it
//!
//! The mirror is the authority for a *verified* pull: on an upstream
//! outage with no cached projection, the npm / PyPI / cargo paths
//! re-project from the mirror, and each version's `shasum` / `integrity`
//! / checksum in that projection is what the subsequent artifact pull
//! verifies against. Unverified mirror bytes make that check circular.
//!
//! `put` therefore records the body's SHA-256 in a fixed-size frame
//! header ahead of the bytes, and `get` verifies the body against it
//! through the same `VerifyingReader` the CAS uses. What that buys is
//! stated precisely in the module doc of `metadata_mirror.rs`: it is
//! integrity at rest, not provenance.

use std::sync::Arc;

use hort_domain::error::DomainError;
use hort_domain::ports::metadata_mirror_store::{mirror_key, MetadataMirrorStore};
use object_store::{ObjectStore, ObjectStoreExt};
use tokio::io::{AsyncRead, AsyncReadExt};

use hort_adapters_storage::{FilesystemMetadataMirror, ObjectStoreMetadataMirror};

/// Mapping id used to build realistic keys.
const MAPPING: &str = "11111111-1111-1111-1111-111111111111";

async fn read_all(mut r: Box<dyn AsyncRead + Send + Unpin>) -> std::io::Result<Vec<u8>> {
    let mut v = Vec::new();
    r.read_to_end(&mut v).await?;
    Ok(v)
}

/// The two production backends, so every invariant below is asserted
/// against both rather than against whichever one is convenient.
fn backends(root: &std::path::Path) -> Vec<(&'static str, Box<dyn MetadataMirrorStore>)> {
    let backing: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    vec![
        (
            "filesystem",
            Box::new(FilesystemMetadataMirror::new(root.to_path_buf())) as Box<_>,
        ),
        (
            "object_store",
            Box::new(ObjectStoreMetadataMirror::new(backing, "memory")) as Box<_>,
        ),
    ]
}

// ---------------------------------------------------------------------------
// 1. The temp subtree
// ---------------------------------------------------------------------------

/// Two keys that differ **only** in extension must not share a temp
/// path. `with_extension` gave both `…/pkg.tmp`; a unique name per write
/// gives them nothing in common.
///
/// Before the fix: `pkg.json` and `pkg.html` both staged through
/// `<root>/meta-mirror/pypi/<id>/pkg.tmp`.
#[tokio::test]
async fn keys_differing_only_in_extension_do_not_share_a_staging_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());

    let json = mirror_key("pypi", MAPPING, "flask.json");
    let html = mirror_key("pypi", MAPPING, "flask.html");

    store
        .put(&json, Box::new(std::io::Cursor::new(b"JSON BODY".to_vec())))
        .await
        .unwrap();
    store
        .put(&html, Box::new(std::io::Cursor::new(b"HTML BODY".to_vec())))
        .await
        .unwrap();

    assert_eq!(
        read_all(store.get(&json).await.unwrap().unwrap())
            .await
            .unwrap(),
        b"JSON BODY",
        "the .json key must still hold its own body"
    );
    assert_eq!(
        read_all(store.get(&html).await.unwrap().unwrap())
            .await
            .unwrap(),
        b"HTML BODY"
    );
}

/// **Counter-test.** Two concurrent `put`s to different keys both land
/// correctly — the per-write unique name is what makes that true, and a
/// shared staging name is what made it false.
#[tokio::test]
async fn concurrent_puts_to_different_keys_both_land() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FilesystemMetadataMirror::new(dir.path().to_path_buf()));

    // Same directory, same stem, different extension — the exact shape
    // `with_extension` collapsed. Bodies are large enough that the two
    // writes genuinely overlap rather than completing one at a time.
    let json = mirror_key("pypi", MAPPING, "flask.json");
    let html = mirror_key("pypi", MAPPING, "flask.html");
    let json_body = vec![b'J'; 512 * 1024];
    let html_body = vec![b'H'; 512 * 1024];

    let a = {
        let (store, key, body) = (Arc::clone(&store), json.clone(), json_body.clone());
        tokio::spawn(async move { store.put(&key, Box::new(std::io::Cursor::new(body))).await })
    };
    let b = {
        let (store, key, body) = (Arc::clone(&store), html.clone(), html_body.clone());
        tokio::spawn(async move { store.put(&key, Box::new(std::io::Cursor::new(body))).await })
    };
    a.await.unwrap().unwrap();
    b.await.unwrap().unwrap();

    assert_eq!(
        read_all(store.get(&json).await.unwrap().unwrap())
            .await
            .unwrap(),
        json_body,
        "concurrent writes must not interleave across keys"
    );
    assert_eq!(
        read_all(store.get(&html).await.unwrap().unwrap())
            .await
            .unwrap(),
        html_body
    );
}

/// Nothing a write stages is reachable through the key interface. The
/// reserved subtree is refused by `resolve` on every method, so a
/// half-written body cannot be served and an orphan cannot be read back
/// — and the refusal cannot be walked around with a `.` segment, which a
/// first-segment-only check would have allowed.
///
/// Before the fix: `<root>/meta-mirror/npm/<id>/express.tmp` was a valid
/// key that `get` served.
#[tokio::test]
async fn the_staging_subtree_is_not_addressable_as_a_key() {
    let dir = tempfile::tempdir().unwrap();

    for (name, store) in backends(dir.path()) {
        for key in [
            ".hort-internal/tmp/anything",
            ".hort-internal/tmp/../../etc/passwd",
            "./.hort-internal/tmp/anything",
            "meta-mirror/npm/x/../../.hort-internal/tmp/anything",
            "/.hort-internal/tmp/anything",
        ] {
            match store.get(key).await {
                Err(DomainError::Validation(_)) => {}
                other => panic!(
                    "{name}: get({key}) must be refused; was_err={}",
                    other.is_err()
                ),
            }
            assert!(
                matches!(
                    store
                        .put(key, Box::new(std::io::Cursor::new(b"x".to_vec())))
                        .await,
                    Err(DomainError::Validation(_))
                ),
                "{name}: put({key}) must be refused"
            );
            assert!(
                matches!(store.delete(key).await, Err(DomainError::Validation(_))),
                "{name}: delete({key}) must be refused"
            );
        }
    }
}

/// A write leaves nothing behind in the addressable keyspace: the
/// staging file is gone after the rename, and the only thing under the
/// mirror root besides the key's own path is the reserved subtree.
#[tokio::test]
async fn a_completed_write_leaves_no_staging_file_in_the_keyspace() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("npm", MAPPING, "express");

    store
        .put(&key, Box::new(std::io::Cursor::new(b"body".to_vec())))
        .await
        .unwrap();

    let mut stray = Vec::new();
    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path.strip_prefix(dir.path()).unwrap().to_path_buf();
            if rel.components().next().map(std::path::Component::as_os_str)
                == Some(".hort-internal".as_ref())
            {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else if rel != std::path::Path::new(&key) {
                stray.push(rel);
            }
        }
    }
    assert!(
        stray.is_empty(),
        "staging residue in the keyspace: {stray:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. The recorded digest
// ---------------------------------------------------------------------------

/// **The finding.** A body altered after it was written is refused on
/// read — the read fails rather than handing back bytes whose digest no
/// longer matches the one recorded with them.
///
/// Before the fix: `get` returned the altered bytes and reported
/// success, so a consumer re-projected them and the `shasum` values in
/// that projection became what the next artifact pull "verified"
/// against.
#[tokio::test]
async fn a_body_altered_at_rest_is_refused_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("npm", MAPPING, "express");
    let body = br#"{"name":"express","versions":{}}"#.to_vec();

    store
        .put(&key, Box::new(std::io::Cursor::new(body.clone())))
        .await
        .unwrap();

    // Same-length substitution, straight on the file — the shape a
    // length check cannot see.
    let path = dir.path().join(&key);
    let on_disk = std::fs::read(&path).unwrap();
    let frame = on_disk.len() - body.len();
    let mut altered = on_disk[..frame].to_vec();
    altered.extend_from_slice(&vec![b'X'; body.len()]);
    assert_eq!(altered.len(), on_disk.len());
    std::fs::write(&path, &altered).unwrap();

    let reader = store
        .get(&key)
        .await
        .expect("the frame header still parses")
        .expect("the key still exists");
    let err = read_all(reader)
        .await
        .expect_err("an altered body must not read back clean");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "got: {err}");
}

/// The same for the object-store backend: the frame travels with the
/// object, so altering the stored object is caught there too.
#[tokio::test]
async fn an_altered_object_store_body_is_refused_on_read() {
    let backing: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let store = ObjectStoreMetadataMirror::new(Arc::clone(&backing), "memory");
    let key = mirror_key("npm", MAPPING, "express");
    let body = b"the original body".to_vec();

    store
        .put(&key, Box::new(std::io::Cursor::new(body.clone())))
        .await
        .unwrap();

    // Rewrite the object behind the port's back, keeping the frame
    // header and substituting the body.
    let path = object_store::path::Path::from(key.as_str());
    let stored = backing.get(&path).await.unwrap().bytes().await.unwrap();
    let frame = stored.len() - body.len();
    let mut altered = stored[..frame].to_vec();
    altered.extend_from_slice(&vec![b'Z'; body.len()]);
    backing
        .put(&path, bytes::Bytes::from(altered).into())
        .await
        .unwrap();

    let reader = store.get(&key).await.unwrap().expect("key exists");
    let err = read_all(reader).await.expect_err("altered body refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// A body that carries no frame at all — anything written by a release
/// before the frame existed, or planted by hand — has no recorded digest
/// to check, so it is refused rather than trusted. Fail-closed: the
/// alternative is an "accept when no digest was recorded" path, which an
/// attacker satisfies by removing the header.
#[tokio::test]
async fn an_unframed_body_is_refused_rather_than_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("npm", MAPPING, "express");

    let path = dir.path().join(&key);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, br#"{"name":"express"}"#).unwrap();

    match store.get(&key).await {
        Err(DomainError::Invariant(msg)) => assert!(
            msg.contains("frame"),
            "the error must name the missing frame; got: {msg}"
        ),
        other => panic!(
            "an unframed body must be refused; was_err={}",
            other.is_err()
        ),
    }
}

/// A truncated body — the frame header survived, the bytes did not — is
/// refused. The digest catches the shortfall the moment the read ends,
/// which is what a length-free mirror read could never do.
#[tokio::test]
async fn a_truncated_body_is_refused_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("cargo", MAPPING, "se/rd/serde");

    store
        .put(&key, Box::new(std::io::Cursor::new(vec![b'q'; 4096])))
        .await
        .unwrap();

    let path = dir.path().join(&key);
    let on_disk = std::fs::read(&path).unwrap();
    std::fs::write(&path, &on_disk[..on_disk.len() - 1]).unwrap();

    let reader = store.get(&key).await.unwrap().expect("key exists");
    assert!(
        read_all(reader).await.is_err(),
        "a truncated body must not read back clean"
    );
}

/// **Counter-test.** An unaltered body still reads back byte-for-byte,
/// on both backends, across put / overwrite / delete. This is the
/// air-gapped and stale-while-error path: if it stops working, an
/// upstream outage stops being survivable.
#[tokio::test]
async fn an_unaltered_body_still_round_trips_on_both_backends() {
    let dir = tempfile::tempdir().unwrap();
    let key = mirror_key("npm", MAPPING, "@types%2fnode");

    for (name, store) in backends(dir.path()) {
        assert!(
            store.get(&key).await.unwrap().is_none(),
            "{name}: absent key is None, not an error"
        );

        store
            .put(&key, Box::new(std::io::Cursor::new(b"v1".to_vec())))
            .await
            .unwrap();
        assert_eq!(
            read_all(store.get(&key).await.unwrap().unwrap())
                .await
                .unwrap(),
            b"v1",
            "{name}: first write"
        );

        // Overwrite with a different length — the frame must be rewritten,
        // not appended to or left describing the old body.
        store
            .put(&key, Box::new(std::io::Cursor::new(b"v2-longer".to_vec())))
            .await
            .unwrap();
        assert_eq!(
            read_all(store.get(&key).await.unwrap().unwrap())
                .await
                .unwrap(),
            b"v2-longer",
            "{name}: overwrite"
        );

        store.delete(&key).await.unwrap();
        assert!(store.get(&key).await.unwrap().is_none(), "{name}: delete");
        store.delete(&key).await.unwrap();
    }
}

/// An empty body round-trips. The frame still records the empty-string
/// digest, so "the file is exactly a frame header and nothing else" is a
/// state the reader accepts rather than mistaking for a truncation.
#[tokio::test]
async fn an_empty_body_round_trips_on_both_backends() {
    let dir = tempfile::tempdir().unwrap();
    let key = mirror_key("pypi", MAPPING, "empty");

    for (name, store) in backends(dir.path()) {
        store
            .put(&key, Box::new(std::io::Cursor::new(Vec::new())))
            .await
            .unwrap();
        assert!(
            read_all(store.get(&key).await.unwrap().unwrap())
                .await
                .unwrap()
                .is_empty(),
            "{name}: empty body"
        );
    }
}

/// A multi-megabyte body round-trips, and the hashing happens as the
/// bytes stream: the backing file is written once, with the digest
/// patched into the header slot afterwards. Nothing here asserts the
/// absence of a buffer directly — that is what the `put` implementation's
/// own loop shows — but a body well past any plausible buffer proves the
/// path is not quietly materialising it twice.
#[tokio::test]
async fn a_large_body_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("npm", MAPPING, "big");
    let body: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    store
        .put(&key, Box::new(std::io::Cursor::new(body.clone())))
        .await
        .unwrap();
    assert_eq!(
        read_all(store.get(&key).await.unwrap().unwrap())
            .await
            .unwrap(),
        body
    );
}

/// Traversal rejection survives the new validator — the package segment
/// is upstream-influenced and is not regex-checked, so this is the
/// defense that was already here and must not have been traded away.
#[tokio::test]
async fn traversal_keys_are_still_refused_on_both_backends() {
    let dir = tempfile::tempdir().unwrap();
    let bad = "meta-mirror/npm/m/../../../etc/passwd";

    for (name, store) in backends(dir.path()) {
        assert!(
            matches!(
                store
                    .put(bad, Box::new(std::io::Cursor::new(b"x".to_vec())))
                    .await,
                Err(DomainError::Validation(_))
            ),
            "{name}: put"
        );
        match store.get(bad).await {
            Err(DomainError::Validation(_)) => {}
            other => panic!("{name}: get was_err={}", other.is_err()),
        }
        assert!(
            matches!(store.delete(bad).await, Err(DomainError::Validation(_))),
            "{name}: delete"
        );
    }
}

/// The filesystem backend's 0600 mode is a standing invariant of the
/// mirror (bodies hold authenticated-upstream metadata). The staged file
/// is created 0600 and the rename preserves the mode, so the digest work
/// must not have introduced a second, laxer creation path.
#[cfg(unix)]
#[tokio::test]
async fn the_framed_file_is_still_mode_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
    let key = mirror_key("npm", MAPPING, "express");

    store
        .put(&key, Box::new(std::io::Cursor::new(b"secret".to_vec())))
        .await
        .unwrap();

    let mode = std::fs::metadata(dir.path().join(&key))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "mirror blob must be 0o600, got {mode:o}");
}

// ---------------------------------------------------------------------------
// The conformance list is the whole production corpus
// ---------------------------------------------------------------------------

/// Everything above is asserted against [`backends`], so [`backends`]
/// being complete is what makes it a contract rather than two spot
/// checks. A third `impl MetadataMirrorStore for …` that stages through a
/// shared name, or hands back its backend's stream unverified, compiles,
/// passes clippy, and passes its own put/get round-trip — an unframed
/// write paired with an unframed read is perfectly self-consistent. The
/// only thing it breaks is a guarantee no test of *its own* would state.
///
/// So: the number of production implementations must equal the number of
/// backends exercised here, and adding one without joining the list is a
/// red test rather than a silent gap. This is the cheap, behavioural form
/// of the argument `crates/hort-app/tests/cas_reads_are_verified.rs`
/// makes structurally for `StoragePort::get` — it checks that each
/// implementation *refuses an altered body*, not that it contains a
/// particular constructor call.
///
/// **Blind spot**, stated rather than papered over: the census matches a
/// line that begins the `impl` at column 0, which is where rustfmt puts a
/// top-level one. An implementation nested inside a module body (indented)
/// or produced by a macro is not counted. That is the same class of blind
/// spot every source scan in this repo carries, and the reason the
/// behavioural assertions above are the primary control.
#[test]
fn every_production_mirror_implementation_is_in_the_conformance_list() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the crate sits at <workspace>/crates/<name>")
        .to_path_buf();

    let mut found: Vec<String> = Vec::new();
    let mut stack = vec![workspace.join("crates")];
    while let Some(at) = stack.pop() {
        for entry in std::fs::read_dir(&at)
            .expect("readable directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                // Adapter crates only — a `#[cfg(test)]` double in an
                // inbound-HTTP crate is not a production implementation,
                // and is excluded by how it is compiled rather than by an
                // entry in a list.
                let name = entry.file_name().to_string_lossy().into_owned();
                let under_adapter = path.components().any(|c| {
                    c.as_os_str()
                        .to_string_lossy()
                        .starts_with("hort-adapters-")
                });
                if under_adapter || name.starts_with("hort-adapters-") {
                    if name == "tests" || name == "target" {
                        continue;
                    }
                    stack.push(path);
                }
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("source is readable UTF-8");
            let mut in_test_module = false;
            for line in source.lines() {
                if line.starts_with("#[cfg(test)]") {
                    in_test_module = true;
                }
                if !in_test_module && line.starts_with("impl MetadataMirrorStore for ") {
                    found.push(format!(
                        "{}: {}",
                        path.strip_prefix(&workspace).unwrap().display(),
                        line.trim()
                    ));
                }
            }
        }
    }
    found.sort();

    assert_eq!(
        found,
        vec![
            "crates/hort-adapters-storage/src/metadata_mirror.rs: \
             impl MetadataMirrorStore for FilesystemMetadataMirror {"
                .to_string(),
            "crates/hort-adapters-storage/src/metadata_mirror.rs: \
             impl MetadataMirrorStore for ObjectStoreMetadataMirror {"
                .to_string(),
        ],
        "the production mirror implementations and the `backends()` \
         conformance list have diverged. A new implementation must be \
         added to `backends()` — and read against the invariants above \
         first: that nothing it stages is addressable as a key, and that \
         it records its body's digest and refuses a body that no longer \
         matches it. Deleting an implementation means deleting its entry. \
         There is no allow-list: an implementation that cannot verify is \
         a review conversation about whether it may back the mirror at all"
    );
    assert_eq!(
        backends(std::path::Path::new("/nonexistent-root-never-touched")).len(),
        found.len(),
        "every production implementation must be exercised by the \
         assertions in this file"
    );
}
