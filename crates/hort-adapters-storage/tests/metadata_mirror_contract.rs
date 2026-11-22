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
//!
//! The digest in that header is supplied by the caller rather than
//! discovered by `put`, and `put` verifies it against the bytes it
//! writes before committing them — which is what lets both backends
//! stream the body through in one forward pass. The refusal of a
//! mis-stated digest, and the atomicity of a refused write, are asserted
//! against both backends in `metadata_mirror.rs`'s own test module,
//! because those are the paths whose coverage the `--lib` gate measures.
//! What this file adds is the third invariant below.
//!
//! ## 3. Neither backend may hold the body
//!
//! An upstream metadata body reaches tens of MiB (ADR 0026), so a `put`
//! that materialises one costs that much resident memory for every
//! refresh running at the same time — the failure ADR 0026 was written
//! to end. Both backends therefore stream, and
//! [`neither_backend_accumulates_the_body`] is the standing control on
//! that: a stored object cannot tell the two shapes apart (a whole-body
//! `put` and a chunked upload leave the same bytes under the key), so
//! the absence of the accumulating idioms is what has to be pinned.

use std::sync::Arc;

use hort_domain::error::DomainError;
use hort_domain::ports::metadata_mirror_store::{body_digest, mirror_key, MetadataMirrorStore};
use object_store::{ObjectStore, ObjectStoreExt};
use tokio::io::{AsyncRead, AsyncReadExt};

use hort_adapters_storage::{FilesystemMetadataMirror, ObjectStoreMetadataMirror};

/// Mapping id used to build realistic keys.
const MAPPING: &str = "11111111-1111-1111-1111-111111111111";

/// `put` `body` under `key` with the digest its own bytes produce, the
/// way the upstream-fetch caller does. The digest comes from the port's
/// own [`body_digest`] rather than a copy typed here: a helper that
/// hashed differently from the one production supplies would make every
/// assertion below about the difference.
async fn put_body(
    store: &dyn MetadataMirrorStore,
    key: &str,
    body: Vec<u8>,
) -> Result<(), DomainError> {
    let supplied = body_digest(&body);
    store
        .put(key, Box::new(std::io::Cursor::new(body)), supplied)
        .await
}

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

    put_body(&store, &json, b"JSON BODY".to_vec())
        .await
        .unwrap();
    put_body(&store, &html, b"HTML BODY".to_vec())
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
        tokio::spawn(async move { put_body(store.as_ref(), &key, body).await })
    };
    let b = {
        let (store, key, body) = (Arc::clone(&store), html.clone(), html_body.clone());
        tokio::spawn(async move { put_body(store.as_ref(), &key, body).await })
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
                    put_body(store.as_ref(), key, b"x".to_vec()).await,
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

    put_body(&store, &key, b"body".to_vec()).await.unwrap();

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

    put_body(&store, &key, body.clone()).await.unwrap();

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

    put_body(&store, &key, body.clone()).await.unwrap();

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

    put_body(&store, &key, vec![b'q'; 4096]).await.unwrap();

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

        put_body(store.as_ref(), &key, b"v1".to_vec())
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
        put_body(store.as_ref(), &key, b"v2-longer".to_vec())
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
        put_body(store.as_ref(), &key, Vec::new()).await.unwrap();
        assert!(
            read_all(store.get(&key).await.unwrap().unwrap())
                .await
                .unwrap()
                .is_empty(),
            "{name}: empty body"
        );
    }
}

/// A body larger than one multipart part round-trips on both backends,
/// in order and without a gap at the seam.
///
/// The size is the point. Both backends write the frame header and then
/// stream the body past it in fixed-size reads, and on the object-store
/// backend those reads are reassembled into 5 MiB parts that reach the
/// store separately — so a body that fits in one part exercises none of
/// the boundary arithmetic. A body of `MULTIPART_PART_SIZE + 1 MiB`
/// crosses the seam once, which is where an off-by-one in the chunking
/// (a dropped or duplicated tail) shows up as a body that no longer
/// hashes to its own frame.
#[tokio::test]
async fn a_body_larger_than_one_part_round_trips_on_both_backends() {
    /// The object-store backend's multipart part size — 5 MiB, the floor
    /// S3-compatible stores impose on a non-final part. Mirrored here so
    /// the body below is sized relative to the real boundary rather than
    /// to a round number that happens to clear it today.
    const MULTIPART_PART_SIZE: usize = 5 * 1024 * 1024;

    let dir = tempfile::tempdir().unwrap();
    let key = mirror_key("npm", MAPPING, "big");
    let body: Vec<u8> = (0..MULTIPART_PART_SIZE + 1024 * 1024)
        .map(|i| (i % 251) as u8)
        .collect();

    for (name, store) in backends(dir.path()) {
        put_body(store.as_ref(), &key, body.clone()).await.unwrap();
        assert_eq!(
            read_all(store.get(&key).await.unwrap().unwrap())
                .await
                .unwrap(),
            body,
            "{name}: a body spanning more than one part must read back whole"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Neither backend holds the body
// ---------------------------------------------------------------------------

/// Production source of the adapter module, with its own test module cut
/// off — the scan below is about what ships, and the test module below it
/// legitimately materialises fixture bodies.
fn production_source() -> &'static str {
    let source = include_str!("../src/metadata_mirror.rs");
    let marker = "\n#[cfg(test)]\n";
    let (production, tests) = source
        .split_once(marker)
        .expect("the adapter module ends with a #[cfg(test)] module at column 0");
    assert!(
        tests.contains("mod tests {"),
        "the split must land on the test module, not on an inner #[cfg(test)] item"
    );
    production
}

/// Idioms that can only appear in this module if a `put` is holding the
/// whole body, each with what it would mean. The list is short because
/// there are only so many shapes: accumulate into a growable buffer,
/// read to the end, or hand a backend a whole payload.
///
/// `.put(` is the last of those and is deliberately unqualified, because
/// the receiver can be spelled several ways and the line break rustfmt
/// chooses moves with it. Its one false positive is a doc comment that
/// spells a call with its parentheses — reword it to name the method
/// instead, which is what every other doc comment in the module already
/// does.
const ACCUMULATING_IDIOMS: &[(&str, &str)] = &[
    (
        "read_to_end",
        "reads a body to its end into a buffer sized by that body",
    ),
    (
        "BytesMut",
        "a growable byte buffer, which nothing on this path needs unless it \
         is accumulating the body",
    ),
    (
        "io::copy",
        "copies a reader into a sink with no bound of its own; the bounded \
         form in this module is an explicit read-chunk loop",
    ),
    (
        ".put(",
        "a single-shot backend put takes one whole payload — there is no \
         shape of that call which is not the entire body in memory",
    ),
];

/// **The finding.** Neither backend may accumulate the body.
///
/// This was the defect: the object-store `put` copied the body into a
/// `Vec` and handed it to `ObjectStore::put`, justified by a comment
/// asserting the body was "small, already-capped". It was not — the
/// caller streams the raw upstream body, which ADR 0026 measured at tens
/// of MiB — so the cost was the body's size times the number of
/// concurrent refreshes. Two comments, each true where it stood, jointly
/// false across the seam between them.
///
/// A source scan rather than a measurement, for the reason given in the
/// module doc: the stored object is identical either way, so there is no
/// behaviour to assert. It is the same form of control as
/// `crates/hort-app/tests/cas_reads_are_verified.rs`, and it carries the
/// same blind spot — an accumulation assembled through a macro, or
/// delegated to a helper named something else, reads as clean. The
/// counter-assertions below are what keep it from going vacuously green.
#[test]
fn neither_backend_accumulates_the_body() {
    let production = production_source();

    for (idiom, why) in ACCUMULATING_IDIOMS {
        assert!(
            !production.contains(idiom),
            "`{idiom}` is back in the metadata mirror: it {why}. An upstream \
             metadata body reaches tens of MiB (ADR 0026) and this port is on \
             the refresh path, so a body-sized allocation here is a body-sized \
             allocation per concurrent refresh."
        );
    }

    // Counter-assertions. A scan for absent text passes just as happily
    // over a file it failed to read, a function that was renamed away, or
    // a predicate that no longer matches anything — so pin that the
    // streaming shape this file is asserting the *presence* of is still
    // here, in both backends.
    for marker in [
        // The filesystem backend's bounded read loop.
        "async fn copy_hashing(",
        // The object-store backend's bounded multipart writer.
        "WriteMultipart::new_with_chunk_size(upload, UPLOAD_CHUNK_SIZE)",
        ".wait_for_capacity(MAX_PARTS_IN_FLIGHT)",
        // The part size the round-trip test above sizes its body
        // against. Pinned here so that test stays a test about the
        // seam rather than about a number that drifted away from it.
        "const UPLOAD_CHUNK_SIZE: usize = 5 * 1024 * 1024;",
    ] {
        assert!(
            production.contains(marker),
            "the streaming shape this guard assumes is gone: {marker:?} is no \
             longer in the module, so the absence of the accumulating idioms \
             above says nothing about how the body is written"
        );
    }
    // Both read loops are bounded by the same named constant, and both
    // are in the scanned region. A `vec!` sized by anything else — a
    // length taken from the body, say — is the accumulation this guard
    // exists to reject, and it would not be spelled with this constant.
    assert_eq!(
        production.matches("vec![0u8; READ_CHUNK]").count(),
        2,
        "each backend reads through one fixed-size buffer; a loop whose \
         buffer is not `READ_CHUNK` is sized by something, and the only \
         other thing in scope is the body"
    );
    assert_eq!(
        production.matches("fn put(").count(),
        2,
        "both backends' `put` must be in the scanned region; a third \
         implementation, or one moved below the test module, is outside it"
    );
    // Two calls to the port's own `require_supplied_digest` in the
    // region that holds both `put`s and both their write helpers. Which
    // helper reaches which call is NOT pinned here — both calls sit in
    // free functions rather than in a `fn put` body, so a per-`put`
    // scope would find none. That each backend actually refuses a
    // mis-stated pair is pinned behaviourally, by
    // `a_put_whose_digest_does_not_match_the_bytes_is_refused_on_both_backends`
    // over `backends()`; this count is the structural backstop that the
    // refusal is still reached in this module at all. The refusal is
    // defined beside the port it belongs to
    // (`hort_domain::ports::metadata_mirror_store`) so that every
    // implementor including the in-memory test double consumes one
    // definition, which is why what this file can pin is the calls and
    // not the definition.
    assert_eq!(
        production.matches("require_supplied_digest(").count(),
        2,
        "each backend must verify the digest it was handed against the \
         bytes it wrote; a `put` that does not reach the refusal commits \
         a body whose own frame header every later `get` will reject"
    );

    // Mutation check. The text below is the object-store `put` as it
    // stood when the audit found it: a placeholder frame, a whole-body
    // copy into a `Vec`, and the resulting payload handed to the store
    // in one shot. The scan has to catch it — a predicate that passes
    // over the exact code it was written for is not a control.
    let the_defect_as_it_shipped = "\
            let mut buf = placeholder_frame_header();\n\
            tokio::io::copy(&mut body, &mut buf).await?;\n\
            self.store.put(&path, bytes::Bytes::from(buf).into()).await?;\n";
    let caught: Vec<&str> = ACCUMULATING_IDIOMS
        .iter()
        .map(|(idiom, _)| *idiom)
        .filter(|idiom| the_defect_as_it_shipped.contains(idiom))
        .collect();
    assert_eq!(
        caught,
        vec!["io::copy", ".put("],
        "the scan must still reject the implementation it replaced"
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
                put_body(store.as_ref(), bad, b"x".to_vec()).await,
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

    put_body(&store, &key, b"secret".to_vec()).await.unwrap();

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
