//! Materialising a composed OCI image as an image layout on disk.
//!
//! The unit of filesystem assessment for an OCI image is the image
//! manifest, not a layer (ADR 0064 D1): a later layer adds packages an
//! earlier one cannot be read for and removes packages it carries, so no
//! composition of per-layer verdicts reconstructs the package set of the
//! thing an operator actually runs. The scanner can assess that
//! composition — `trivy image --input <dir>` over an OCI image layout
//! applies the layers in manifest order, resolves whiteouts and opaque
//! whiteouts, and derives the OS identity from the composed tree — but
//! only if hort hands it the layout. This module writes that layout.
//!
//! # The layout
//!
//! Three things, per the OCI image-layout specification:
//!
//! ```text
//! <dir>/oci-layout                    {"imageLayoutVersion":"1.0.0"}
//! <dir>/index.json                    one descriptor, naming the manifest
//! <dir>/blobs/sha256/<hex>            the manifest, the config, every layer
//! ```
//!
//! `index.json` is written **last**, after every blob is in place, so a
//! directory that is still being assembled is not yet recognisable as a
//! layout at all.
//!
//! # Blobs are copied verbatim
//!
//! Nothing here decompresses a layer — and it is not a shortcut that it
//! does not. The layout path *is* the digest of the bytes it holds, and
//! the manifest's descriptors address each blob by that digest, so a
//! materialisation that decompressed on the way in would write a file
//! whose name no longer described its contents. The scanner decompresses;
//! hort's own decoder inventory is irrelevant on this path, which is why
//! [`layer_media_type_is_openable`](hort_domain::oci) is the *scanner's*
//! measured reach rather than this crate's.
//!
//! Every blob comes out of storage through `StoragePort::get`, the
//! verified read path (ADR 0003), so the name the layout gives a blob is
//! a claim the read itself checked.
//!
//! # Fail-closed: never a partial layout
//!
//! A constituent that is missing, unreadable, or over the whole-image
//! budget yields **no verdict** — never a partial layout and never a
//! clean verdict over a subset. A layout missing a layer is not a broken
//! layout: it is a *complete-looking* image with fewer layers, which the
//! scanner cannot detect and will happily report a clean inventory for.
//! So every refusal removes the directory it was building before
//! returning.
//!
//! What the refusal then becomes depends on its own answer to "would
//! running this again help" ([`LayoutRefusal::is_transient`]). A refusal
//! about the **image** — more constituents or more bytes than hort will
//! assemble, or a constituent that is not in CAS — becomes
//! [`NotAnalysable::IncompleteComposition`](hort_domain::ports::scanner::NotAnalysable::IncompleteComposition),
//! a value no assembled composition can produce and one the job queue
//! will not spin on. A refusal about the **machine** — a stalled storage
//! stream, a failed read, a full scratch disk — becomes an error, which
//! is the answer the orchestrator already reschedules under the scan job's
//! own attempt budget. Both are the absence of a verdict; only one of them
//! can be different next time.
//!
//! # The budget is the image's, not each blob's
//!
//! The single-blob path bounds one artifact (8 GiB copied, 4 GiB
//! extracted). A composition reads N blobs, so reusing a per-blob bound
//! would multiply it by the layer count — and 1024 descriptors is a
//! manifest the strict parse calls well-formed. [`ImageBudget`] bounds
//! the image instead: bytes written (which on this path *is* the
//! scratch-disk footprint), constituents copied, and wall-clock for the
//! assembly.

use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use hort_domain::error::DomainError;
use hort_domain::oci::ImageBudget;
use hort_domain::ports::scanner::ComposedImage;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use crate::workspace::{copy_capped, BoundedCopy};

/// `imageLayoutVersion` of the layout this module writes — the only
/// version the OCI image-layout specification defines.
const IMAGE_LAYOUT_VERSION: &str = "1.0.0";

/// The marker file that makes a directory an OCI image layout.
const OCI_LAYOUT_FILE: &str = "oci-layout";

/// The layout's entry point: an image index naming the manifest to read.
const INDEX_FILE: &str = "index.json";

/// Where a layout's blobs live, relative to its root. The second segment
/// is the digest algorithm, and hort's CAS is SHA-256 throughout.
const BLOBS_SUBDIR: &str = "blobs";
const SHA256_SUBDIR: &str = "sha256";

/// Which constituent of a composition a refusal is about.
///
/// [`Layer`](Self::Layer) carries the **zero-based index in manifest
/// order** — the order the layers are applied in — so a refusal names a
/// position a reader can find in the manifest bytes rather than a digest
/// they have to search for. Same convention as
/// [`ImageDescriptorSlot`](hort_domain::oci::ImageDescriptorSlot), with
/// the manifest itself added: on this path the manifest is a blob the
/// layout has to hold, not just the document that named the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Constituent {
    /// The image manifest blob.
    Manifest,
    /// The image config blob.
    Config,
    /// `layers[N]`, zero-based in manifest order.
    Layer(usize),
}

impl fmt::Display for Constituent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest => f.write_str("manifest"),
            Self::Config => f.write_str("config"),
            Self::Layer(index) => write!(f, "layers[{index}]"),
        }
    }
}

/// Why a layout was not assembled.
///
/// Every variant is the absence of a layout, and the caller maps all of
/// them to the one fail-closed outcome — the variants exist so the log
/// line names what was refused and which constituent it was about. The
/// offending constituent is named by slot *and* digest because a
/// composition is a set of references and "which one" is the operator's
/// first question.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub(crate) enum LayoutRefusal {
    /// A constituent is not in storage, or its read failed — which
    /// includes the verified read path rejecting the bytes it served.
    /// `fault` is what tells those apart for the retry decision.
    #[error("{which} (sha256:{hash}) could not be read from storage: {detail}")]
    ConstituentUnreadable {
        /// Which constituent.
        which: Constituent,
        /// Its declared digest.
        hash: ContentHash,
        /// Whether the read said "there is no such object" or "the read
        /// failed" — the two the caller must not conflate, which is why it
        /// is a value here rather than a shape in `detail`.
        fault: ConstituentFault,
        /// What the read said.
        detail: String,
    },
    /// More constituents than [`ImageBudget::max_blobs`]. Refused before
    /// any blob is read: the cheapest refusal, and the one that keeps the
    /// other two bounds from being reached N times over.
    #[error("image declares {declared} constituents; the whole-image budget allows {max}")]
    TooManyConstituents {
        /// Manifest + config + layers.
        declared: usize,
        /// The bound.
        max: usize,
    },
    /// The constituents written so far exceeded
    /// [`ImageBudget::max_bytes`]. Names the constituent that tripped it,
    /// which is the one an operator would otherwise have to find by
    /// subtracting sizes.
    #[error("{which} (sha256:{hash}) exceeded the whole-image byte budget ({max} bytes)")]
    ByteBudget {
        /// The constituent being copied when the budget ran out.
        which: Constituent,
        /// Its declared digest.
        hash: ContentHash,
        /// The bound.
        max: u64,
    },
    /// The assembly took longer than [`ImageBudget::max_duration`].
    #[error("assembling the image layout exceeded its wall-clock budget ({secs}s)")]
    TimeBudget {
        /// The bound, in seconds.
        secs: u64,
    },
    /// The layout could not be written — a full or read-only scratch
    /// disk, not a property of the image.
    #[error("could not write the image layout: {0}")]
    Unwritable(String),
}

/// Why a constituent's CAS read did not produce bytes.
///
/// The distinction is not cosmetic: it is what decides whether re-running
/// the composition can change the answer. A constituent with **no** CAS
/// object is the state acquisition either resolved or could not resolve
/// (a hosted repository has no upstream to resolve it from), so the next
/// attempt reads the same absence. A storage backend that **failed** is a
/// liveness condition that re-running may well clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConstituentFault {
    /// There is no CAS object at that digest.
    Absent,
    /// The read reached storage and did not complete.
    Backend,
}

impl LayoutRefusal {
    /// Whether re-running the composition could plausibly succeed.
    ///
    /// Exhaustive, deliberately: a future refusal has to state which side
    /// of the retry decision it falls on rather than inheriting one. The
    /// `false` arms are refusals whose cause is the *image* — it declares
    /// more constituents or more bytes than hort will assemble, or a
    /// constituent is simply not here — and re-running an over-budget
    /// image is pure delay. The `true` arms are refusals whose cause is
    /// the *machine*: a stalled storage stream, a failed read, a full
    /// scratch disk.
    ///
    /// A transient refusal is surfaced to the orchestrator as a backend
    /// **error**, which is the path it already reschedules under the scan
    /// job's existing attempt budget; a deterministic one stays
    /// [`NotAnalysable::IncompleteComposition`](hort_domain::ports::scanner::NotAnalysable::IncompleteComposition),
    /// which gates and is never retried.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Self::ConstituentUnreadable { fault, .. } => match fault {
                ConstituentFault::Absent => false,
                ConstituentFault::Backend => true,
            },
            Self::TooManyConstituents { .. } | Self::ByteBudget { .. } => false,
            Self::TimeBudget { .. } | Self::Unwritable(_) => true,
        }
    }
}

/// What an assembled layout cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutStats {
    /// Constituents actually copied. Lower than
    /// [`ComposedImage::constituent_count`] when a manifest declares the
    /// same layer digest twice.
    pub(crate) blobs: usize,
    /// Bytes written across every blob.
    pub(crate) bytes: u64,
}

/// Write `image` into `layout_dir` as an OCI image layout, under
/// `budget`.
///
/// `layout_dir` must already exist and should be empty — the caller owns
/// it (a `TempDir` subdirectory in production) and this function owns its
/// contents.
///
/// **On any refusal `layout_dir` is removed**, so there is no partial
/// layout for a later caller to mistake for a complete one. That is a
/// guarantee of this function rather than of the caller's RAII, because
/// it is the property the whole path turns on: the RAII cleanup covers
/// the production workspace, and this covers the statement.
pub(crate) async fn write_image_layout(
    storage: &Arc<dyn StoragePort>,
    image: &ComposedImage,
    layout_dir: &Path,
    budget: ImageBudget,
) -> Result<LayoutStats, LayoutRefusal> {
    // The timeout wraps the whole assembly: cancelling it drops the
    // in-flight copy, and the cleanup below removes whatever had landed.
    let assembled = match tokio::time::timeout(
        budget.max_duration,
        assemble(storage, image, layout_dir, budget),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(LayoutRefusal::TimeBudget {
            secs: budget.max_duration.as_secs(),
        }),
    };

    if assembled.is_err() {
        discard(layout_dir).await;
    }
    assembled
}

/// The assembly itself: every blob, then the two layout files.
async fn assemble(
    storage: &Arc<dyn StoragePort>,
    image: &ComposedImage,
    layout_dir: &Path,
    budget: ImageBudget,
) -> Result<LayoutStats, LayoutRefusal> {
    let declared = image.constituent_count();
    if declared > budget.max_blobs {
        return Err(LayoutRefusal::TooManyConstituents {
            declared,
            max: budget.max_blobs,
        });
    }

    let blobs_dir = layout_dir.join(BLOBS_SUBDIR).join(SHA256_SUBDIR);
    tokio::fs::create_dir_all(&blobs_dir)
        .await
        .map_err(|e| LayoutRefusal::Unwritable(format!("blobs directory: {e}")))?;

    // Manifest first, then config, then the layers in the order they are
    // applied. The order is the manifest's own, and it is what the
    // refusal's `layers[N]` index refers to.
    let constituents = std::iter::once((Constituent::Manifest, image.manifest()))
        .chain(std::iter::once((Constituent::Config, image.config())))
        .chain(
            image
                .layers()
                .iter()
                .enumerate()
                .map(|(index, layer)| (Constituent::Layer(index), &layer.hash)),
        );

    let mut written: u64 = 0;
    let mut copied: usize = 0;
    // `index.json`'s descriptor has to state the manifest blob's size, and
    // the honest source for it is the copy that just wrote it. `Option`
    // rather than a `0` default: a descriptor claiming a zero-byte
    // manifest is a layout that describes something hort does not hold,
    // and a default is how that would arrive silently.
    let mut manifest_size: Option<u64> = None;
    // A manifest may declare the same layer digest twice (a repeated
    // empty layer is the common case). The layout addresses a blob by its
    // digest, so the second copy would be the same file written again:
    // skip it, and do not charge the budget twice for one file on disk.
    let mut seen: HashSet<&ContentHash> = HashSet::new();
    for (which, hash) in constituents {
        if !seen.insert(hash) {
            continue;
        }
        let path = blobs_dir.join(hash.as_ref());
        let remaining = budget.max_bytes - written;
        match copy_capped(storage, hash, &path, remaining).await {
            Ok(BoundedCopy::Written(bytes)) => {
                written += bytes;
                copied += 1;
                if which == Constituent::Manifest {
                    manifest_size = Some(bytes);
                }
            }
            Ok(BoundedCopy::OverCap) => {
                return Err(LayoutRefusal::ByteBudget {
                    which,
                    hash: hash.clone(),
                    max: budget.max_bytes,
                })
            }
            // A missing blob and a failed read are both "this
            // constituent did not arrive, so there is no composition" —
            // but they are not the same answer to "would running this
            // again help", so the fault class travels with the refusal.
            // It is read off the typed error, not off the message:
            // `StoragePort::get` reports an absent object as
            // `DomainError::NotFound` and nothing else does.
            Err(e) => {
                return Err(LayoutRefusal::ConstituentUnreadable {
                    which,
                    hash: hash.clone(),
                    fault: match e {
                        DomainError::NotFound { .. } => ConstituentFault::Absent,
                        _ => ConstituentFault::Backend,
                    },
                    detail: read_failure_detail(&e),
                })
            }
        }
    }

    // The manifest is the first constituent, so the loop above always
    // copied it — nothing can have skipped it as a duplicate, since it is
    // what seeds the dedup set.
    let manifest_size =
        manifest_size.expect("the manifest is the first constituent and is always copied");

    // Both layout files last, so a directory still being assembled is
    // not yet readable as a layout.
    write_json(
        &layout_dir.join(OCI_LAYOUT_FILE),
        &serde_json::json!({ "imageLayoutVersion": IMAGE_LAYOUT_VERSION }),
    )
    .await?;
    write_json(
        &layout_dir.join(INDEX_FILE),
        &serde_json::json!({
            "schemaVersion": 2,
            "mediaType": hort_domain::oci::OCI_IMAGE_INDEX_MEDIA_TYPE,
            "manifests": [{
                // The media type travels from the manifest's own bytes
                // (never from the stored row's `content_type`, which is
                // a header an upstream supplied), and the size is what
                // the copy above actually wrote — so the descriptor
                // describes the blob beside it rather than restating a
                // claim from elsewhere.
                "mediaType": image.manifest_media_type(),
                "digest": format!("sha256:{}", image.manifest()),
                "size": manifest_size,
            }],
        }),
    )
    .await?;

    Ok(LayoutStats {
        blobs: copied,
        bytes: written,
    })
}

/// Write `value` to `path`. The only thing that can go wrong is the
/// disk, which is not an image problem — and is still a refusal, because
/// a layout missing its `index.json` is not a layout.
///
/// `Value::to_string` rather than `serde_json::to_vec`: serialising a
/// `Value` that was built in this module cannot fail, and a `Result` for
/// it would be an error arm no input can reach.
async fn write_json(path: &Path, value: &serde_json::Value) -> Result<(), LayoutRefusal> {
    tokio::fs::write(path, value.to_string())
        .await
        .map_err(|e| LayoutRefusal::Unwritable(format!("writing {}: {e}", path.display())))
}

/// Remove a refused layout, so nothing downstream can read a partial one.
///
/// A cleanup failure is logged and not propagated: the refusal the caller
/// is about to return is the operative fact, and in production the
/// directory sits inside a `TempDir` whose `Drop` sweeps it anyway.
async fn discard(layout_dir: &Path) {
    match tokio::fs::remove_dir_all(layout_dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(
            scanner = "trivy",
            error = %e,
            "trivy adapter: could not remove a refused image layout",
        ),
    }
}

/// The part of a storage failure worth putting in a refusal message.
///
/// `DomainError`'s `Display` is already the operator-facing text for each
/// variant; this exists so a `NotFound` reads as the plain fact it is
/// rather than as a nested entity/id pair, since "the blob is not here"
/// is the single most likely reason a composition cannot be assembled
/// (a pull-through manifest's layers are registered by digest with no
/// existence check).
fn read_failure_detail(error: &DomainError) -> String {
    match error {
        DomainError::NotFound { .. } => "not present in storage".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::io::Cursor;
    use std::time::Duration;

    use hort_domain::error::DomainResult;
    use hort_domain::oci::{ImageLayout, ImageLayoutLayer, OCI_IMAGE_MANIFEST_MEDIA_TYPE};
    use hort_domain::ports::storage::PutResult;
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::ByteRange;
    use tokio::io::AsyncRead;

    /// The gzip-tar layer media type — what nearly every image in
    /// circulation declares.
    const GZIP_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

    // The fixtures' digests are the **real** SHA-256 of their bytes, so
    // the "a blob sits at the path its digest names" assertion is a claim
    // about the digest and not a tautology about whatever string the test
    // happened to pass in. Recomputable with `printf '%s' <bytes> |
    // sha256sum`.
    const MANIFEST_BYTES: &[u8] = b"{manifest}";
    const MANIFEST_HASH: &str = "b0664121b9077a58a689d751320f151041a1d8c668d9fde8d9918292a3b160ff";
    const CONFIG_BYTES: &[u8] = b"{config}";
    const CONFIG_HASH: &str = "b63ba48e88de2816a6cfde3b3d4487cce19ea9c7db4cb113f052925c10f7f292";
    /// Gzip magic followed by filler: the point is that the layer reaches
    /// the layout still compressed.
    const LAYER_BYTES: &[u8] = b"\x1f\x8b\x08\x00layer-one-compressed";
    const LAYER_HASH: &str = "d05d7132555e825ef9970dd36c13b42d5007694d6779cee4b8bac58b11643f16";
    const SECOND_LAYER_BYTES: &[u8] = b"\x1f\x8b\x08\x00layer-two-compressed";
    const SECOND_LAYER_HASH: &str =
        "0eb7ce7c16b554d3a51301b64eb109bb82a82cf52157894b8ebd8387ff169d3b";

    fn hash(hex: &str) -> ContentHash {
        hex.parse().expect("fixture digest is 64 lowercase hex")
    }

    /// Storage that serves a fixed byte string per hash and `NotFound`
    /// for anything else — which is what makes the "a missing
    /// constituent names itself" assertion reachable without a backend.
    struct MapStorage {
        objects: HashMap<ContentHash, Vec<u8>>,
    }

    impl MapStorage {
        fn with(entries: &[(&str, &[u8])]) -> Arc<dyn StoragePort> {
            Arc::new(Self {
                objects: entries
                    .iter()
                    .map(|(hex, bytes)| (hash(hex), bytes.to_vec()))
                    .collect(),
            })
        }

        /// Every constituent of [`two_layer_image`] present.
        fn complete() -> Arc<dyn StoragePort> {
            Self::with(&[
                (MANIFEST_HASH, MANIFEST_BYTES),
                (CONFIG_HASH, CONFIG_BYTES),
                (LAYER_HASH, LAYER_BYTES),
                (SECOND_LAYER_HASH, SECOND_LAYER_BYTES),
            ])
        }
    }

    impl StoragePort for MapStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!("the layout never writes to storage") })
        }
        fn get(
            &self,
            hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            let found = self.objects.get(hash).cloned();
            let id = hash.to_string();
            Box::pin(async move {
                match found {
                    Some(bytes) => {
                        let reader: Box<dyn AsyncRead + Send + Unpin> =
                            Box::new(Cursor::new(bytes));
                        Ok(reader)
                    }
                    None => Err(DomainError::NotFound {
                        entity: "content",
                        id,
                    }),
                }
            })
        }
        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!("the layout reads whole blobs") })
        }
        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { unreachable!("test stub") })
        }
    }

    /// A two-layer image: gzip layers in a declared order the layout has
    /// to preserve.
    fn two_layer_image() -> ComposedImage {
        ComposedImage::new(
            hash(MANIFEST_HASH),
            ImageLayout {
                config: hash(CONFIG_HASH),
                layers: vec![
                    ImageLayoutLayer {
                        hash: hash(LAYER_HASH),
                        media_type: GZIP_LAYER.to_string(),
                    },
                    ImageLayoutLayer {
                        hash: hash(SECOND_LAYER_HASH),
                        media_type: GZIP_LAYER.to_string(),
                    },
                ],
                manifest_media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
            },
        )
    }

    /// A fresh, empty layout directory inside a `TempDir` the caller
    /// keeps alive — the production shape, and the one that lets a test
    /// observe whether a refusal left anything behind.
    fn layout_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("image");
        std::fs::create_dir(&dir).expect("create layout dir");
        (tmp, dir)
    }

    fn blob_path(dir: &Path, hex: &str) -> std::path::PathBuf {
        dir.join(BLOBS_SUBDIR).join(SHA256_SUBDIR).join(hex)
    }

    // -- the layout is a layout ------------------------------------------

    #[tokio::test]
    async fn an_assembled_layout_is_a_valid_oci_image_layout() {
        let (_tmp, dir) = layout_dir();
        let image = two_layer_image();
        let stats = write_image_layout(
            &MapStorage::complete(),
            &image,
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect("every constituent is present");

        // `oci-layout` is what makes the directory a layout at all.
        let marker = std::fs::read(dir.join(OCI_LAYOUT_FILE)).expect("oci-layout written");
        let marker: serde_json::Value =
            serde_json::from_slice(&marker).expect("oci-layout is JSON");
        assert_eq!(marker["imageLayoutVersion"], IMAGE_LAYOUT_VERSION);

        // `index.json` names the manifest — by digest, with the media
        // type the manifest's own bytes declared and the size actually
        // written.
        let index = std::fs::read(dir.join(INDEX_FILE)).expect("index.json written");
        let index: serde_json::Value = serde_json::from_slice(&index).expect("index.json is JSON");
        assert_eq!(index["schemaVersion"], 2);
        let descriptors = index["manifests"].as_array().expect("manifests array");
        assert_eq!(
            descriptors.len(),
            1,
            "a composition is one manifest, never a set"
        );
        assert_eq!(
            descriptors[0]["digest"],
            format!("sha256:{MANIFEST_HASH}"),
            "index.json must name the manifest the composition is of"
        );
        assert_eq!(descriptors[0]["mediaType"], OCI_IMAGE_MANIFEST_MEDIA_TYPE);
        assert_eq!(
            descriptors[0]["size"],
            serde_json::json!(MANIFEST_BYTES.len()),
            "the descriptor's size is what the copy wrote, not a restated claim"
        );

        // Every constituent sits at `blobs/sha256/<its digest>` and is
        // byte-identical to what storage served. Nothing decompressed:
        // the gzip magic is still the first two bytes of the layer.
        for (hex, bytes) in [
            (MANIFEST_HASH, MANIFEST_BYTES),
            (CONFIG_HASH, CONFIG_BYTES),
            (LAYER_HASH, LAYER_BYTES),
            (SECOND_LAYER_HASH, SECOND_LAYER_BYTES),
        ] {
            let on_disk = std::fs::read(blob_path(&dir, hex)).expect("blob written at its digest");
            assert_eq!(
                on_disk, bytes,
                "the blob at sha256:{hex} must be the bytes storage served, verbatim"
            );
        }
        assert_eq!(
            &std::fs::read(blob_path(&dir, LAYER_HASH)).unwrap()[..2],
            &[0x1f, 0x8b],
            "a decompressed layer would be a file whose name no longer described it"
        );

        assert_eq!(stats.blobs, 4, "manifest + config + two layers");
        assert_eq!(
            stats.bytes,
            (MANIFEST_BYTES.len()
                + CONFIG_BYTES.len()
                + LAYER_BYTES.len()
                + SECOND_LAYER_BYTES.len()) as u64
        );
    }

    /// A manifest's declared media type travels into the descriptor — a
    /// Docker-schema push is a composition too, and `index.json` has to
    /// say so rather than relabelling it.
    #[tokio::test]
    async fn the_index_descriptor_carries_the_manifests_own_media_type() {
        let (_tmp, dir) = layout_dir();
        let docker = "application/vnd.docker.distribution.manifest.v2+json";
        let image = ComposedImage::new(
            hash(MANIFEST_HASH),
            ImageLayout {
                config: hash(CONFIG_HASH),
                layers: vec![ImageLayoutLayer {
                    hash: hash(LAYER_HASH),
                    media_type: GZIP_LAYER.to_string(),
                }],
                manifest_media_type: docker.to_string(),
            },
        );
        write_image_layout(
            &MapStorage::complete(),
            &image,
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect("assembles");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(INDEX_FILE)).unwrap()).unwrap();
        assert_eq!(index["manifests"][0]["mediaType"], docker);
    }

    /// A layer declared twice is one file on disk, charged once. The
    /// layout addresses a blob by its digest, so a second copy would be
    /// the same path written again.
    #[tokio::test]
    async fn a_repeated_layer_digest_is_copied_once() {
        let (_tmp, dir) = layout_dir();
        let image = ComposedImage::new(
            hash(MANIFEST_HASH),
            ImageLayout {
                config: hash(CONFIG_HASH),
                layers: vec![
                    ImageLayoutLayer {
                        hash: hash(LAYER_HASH),
                        media_type: GZIP_LAYER.to_string(),
                    },
                    ImageLayoutLayer {
                        hash: hash(LAYER_HASH),
                        media_type: GZIP_LAYER.to_string(),
                    },
                ],
                manifest_media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
            },
        );
        let stats = write_image_layout(
            &MapStorage::complete(),
            &image,
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect("assembles");
        assert_eq!(stats.blobs, 3, "manifest + config + one distinct layer");
        assert_eq!(
            stats.bytes,
            (MANIFEST_BYTES.len() + CONFIG_BYTES.len() + LAYER_BYTES.len()) as u64,
            "one file on disk is charged to the budget once"
        );
    }

    // -- a missing constituent -------------------------------------------

    /// The refusal names the constituent *and* its digest, and leaves no
    /// directory behind. Acquiring a blob that is not local belongs to
    /// another unit; this one has to say precisely which one was absent.
    #[tokio::test]
    async fn a_missing_layer_is_refused_by_name_with_no_layout_left_behind() {
        let (_tmp, dir) = layout_dir();
        let storage = MapStorage::with(&[
            (MANIFEST_HASH, MANIFEST_BYTES),
            (CONFIG_HASH, CONFIG_BYTES),
            (LAYER_HASH, LAYER_BYTES),
            // The second layer is deliberately absent.
        ]);
        let refusal = write_image_layout(
            &storage,
            &two_layer_image(),
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect_err("a composition missing a layer is not a composition");
        assert_eq!(
            refusal,
            LayoutRefusal::ConstituentUnreadable {
                which: Constituent::Layer(1),
                hash: hash(SECOND_LAYER_HASH),
                fault: ConstituentFault::Absent,
                detail: "not present in storage".to_string(),
            }
        );
        let rendered = refusal.to_string();
        assert!(rendered.contains("layers[1]"), "{rendered}");
        assert!(rendered.contains(SECOND_LAYER_HASH), "{rendered}");
        assert!(
            !dir.exists(),
            "a partial layout is a complete-looking image with fewer layers"
        );
    }

    /// The same posture for the two non-layer constituents, and the slot
    /// names them rather than reporting a layer index.
    #[tokio::test]
    async fn a_missing_manifest_or_config_names_its_own_slot() {
        for (present, expected) in [
            (
                vec![(CONFIG_HASH, CONFIG_BYTES), (LAYER_HASH, LAYER_BYTES)],
                (Constituent::Manifest, MANIFEST_HASH),
            ),
            (
                vec![(MANIFEST_HASH, MANIFEST_BYTES), (LAYER_HASH, LAYER_BYTES)],
                (Constituent::Config, CONFIG_HASH),
            ),
        ] {
            let (_tmp, dir) = layout_dir();
            let refusal = write_image_layout(
                &MapStorage::with(&present),
                &two_layer_image(),
                &dir,
                ImageBudget::default_for_composite_scan(),
            )
            .await
            .expect_err("an absent constituent is a refusal");
            assert_eq!(
                refusal,
                LayoutRefusal::ConstituentUnreadable {
                    which: expected.0,
                    hash: hash(expected.1),
                    fault: ConstituentFault::Absent,
                    detail: "not present in storage".to_string(),
                }
            );
            assert!(!dir.exists());
        }
    }

    /// A read that fails for a reason *other* than absence — a storage
    /// outage, or the verified read path rejecting the bytes it served —
    /// is the same refusal with the backend's own words in the detail.
    #[tokio::test]
    async fn an_unreadable_constituent_carries_the_storage_error() {
        struct FailingRead;
        impl StoragePort for FailingRead {
            fn put(
                &self,
                _stream: Box<dyn AsyncRead + Send + Unpin>,
            ) -> BoxFuture<'_, DomainResult<PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(
                &self,
                _hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async {
                    Err(DomainError::Invariant(
                        "content hash mismatch on read".to_string(),
                    ))
                })
            }
            fn get_range(
                &self,
                _hash: &ContentHash,
                _range: ByteRange,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async { unreachable!() })
            }
            fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { unreachable!() })
            }
            fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
                Box::pin(async { unreachable!() })
            }
            fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }
        let (_tmp, dir) = layout_dir();
        let storage: Arc<dyn StoragePort> = Arc::new(FailingRead);
        let refusal = write_image_layout(
            &storage,
            &two_layer_image(),
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect_err("an unreadable constituent is a refusal");
        let LayoutRefusal::ConstituentUnreadable {
            which,
            fault,
            detail,
            ..
        } = refusal
        else {
            panic!("expected an unreadable constituent, got {refusal:?}");
        };
        assert_eq!(which, Constituent::Manifest);
        assert_eq!(
            fault,
            ConstituentFault::Backend,
            "a read that reached storage and failed is not the same answer as an absence"
        );
        assert!(
            detail.contains("content hash mismatch"),
            "the verified read path's verdict must survive into the refusal: {detail}"
        );
        assert!(!dir.exists());
    }

    // -- each budget ------------------------------------------------------

    #[tokio::test]
    async fn the_constituent_budget_refuses_before_any_blob_is_read() {
        let (_tmp, dir) = layout_dir();
        // Storage that panics on any read, so "before any blob is read"
        // is asserted by construction rather than by a counter.
        struct NoReads;
        impl StoragePort for NoReads {
            fn put(
                &self,
                _stream: Box<dyn AsyncRead + Send + Unpin>,
            ) -> BoxFuture<'_, DomainResult<PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(
                &self,
                _hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                panic!("the constituent budget must refuse before reading anything")
            }
            fn get_range(
                &self,
                _hash: &ContentHash,
                _range: ByteRange,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async { unreachable!() })
            }
            fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { unreachable!() })
            }
            fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
                Box::pin(async { unreachable!() })
            }
            fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }
        let storage: Arc<dyn StoragePort> = Arc::new(NoReads);
        let refusal = write_image_layout(
            &storage,
            &two_layer_image(),
            &dir,
            ImageBudget {
                max_blobs: 3,
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .expect_err("four constituents do not fit a budget of three");
        assert_eq!(
            refusal,
            LayoutRefusal::TooManyConstituents {
                declared: 4,
                max: 3,
            }
        );
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn the_byte_budget_refuses_and_leaves_no_partial_layout() {
        let (_tmp, dir) = layout_dir();
        // Enough for the manifest and the config, not for the layers.
        let max_bytes = (MANIFEST_BYTES.len() + CONFIG_BYTES.len() + 1) as u64;
        let refusal = write_image_layout(
            &MapStorage::complete(),
            &two_layer_image(),
            &dir,
            ImageBudget {
                max_bytes,
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .expect_err("the image does not fit the whole-image byte budget");
        assert_eq!(
            refusal,
            LayoutRefusal::ByteBudget {
                which: Constituent::Layer(0),
                hash: hash(LAYER_HASH),
                max: max_bytes,
            },
            "the refusal names the constituent that ran the budget out"
        );
        assert!(
            !dir.exists(),
            "the manifest and config were already on disk; a clean verdict over \
             that subset is exactly what must not be possible"
        );
    }

    /// An image whose total is *exactly* the budget assembles — the
    /// at-cap boundary is not a refusal, the same off-by-one the
    /// single-blob copy gets right.
    #[tokio::test]
    async fn an_image_exactly_at_the_byte_budget_assembles() {
        let (_tmp, dir) = layout_dir();
        let exact = (MANIFEST_BYTES.len()
            + CONFIG_BYTES.len()
            + LAYER_BYTES.len()
            + SECOND_LAYER_BYTES.len()) as u64;
        let stats = write_image_layout(
            &MapStorage::complete(),
            &two_layer_image(),
            &dir,
            ImageBudget {
                max_bytes: exact,
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .expect("an image that exactly fits the budget fits it");
        assert_eq!(stats.bytes, exact);
        assert!(dir.join(INDEX_FILE).exists());
    }

    #[tokio::test(start_paused = true)]
    async fn the_wall_clock_budget_refuses_and_leaves_no_partial_layout() {
        /// Storage whose stream never yields: the stall this bound
        /// exists for, since the scanner's own timeout only starts once
        /// the layout exists.
        struct Stalled;
        struct NeverReady;
        impl AsyncRead for NeverReady {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }
        impl StoragePort for Stalled {
            fn put(
                &self,
                _stream: Box<dyn AsyncRead + Send + Unpin>,
            ) -> BoxFuture<'_, DomainResult<PutResult>> {
                Box::pin(async { unreachable!() })
            }
            fn get(
                &self,
                _hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async {
                    let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(NeverReady);
                    Ok(reader)
                })
            }
            fn get_range(
                &self,
                _hash: &ContentHash,
                _range: ByteRange,
            ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
                Box::pin(async { unreachable!() })
            }
            fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
                Box::pin(async { unreachable!() })
            }
            fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
                Box::pin(async { unreachable!() })
            }
            fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { unreachable!() })
            }
        }
        let (_tmp, dir) = layout_dir();
        let storage: Arc<dyn StoragePort> = Arc::new(Stalled);
        let refusal = write_image_layout(
            &storage,
            &two_layer_image(),
            &dir,
            ImageBudget {
                max_duration: Duration::from_secs(30),
                ..ImageBudget::default_for_composite_scan()
            },
        )
        .await
        .expect_err("a stalled storage stream must not hold a worker slot forever");
        assert_eq!(refusal, LayoutRefusal::TimeBudget { secs: 30 });
        assert!(!dir.exists());
    }

    /// A disk the layout cannot be written to is a refusal too — a layout
    /// without its `index.json` is not a layout. Reached by removing the
    /// directory under the assembly, which is the one failure a test can
    /// provoke without a read-only mount.
    #[tokio::test]
    async fn an_unwritable_layout_directory_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("never-created");
        // `create_dir_all` under a path whose parent is a *file* cannot
        // succeed, so the blobs directory fails before any read.
        std::fs::write(tmp.path().join("never-created"), b"not a directory")
            .expect("write the blocking file");
        let refusal = write_image_layout(
            &MapStorage::complete(),
            &two_layer_image(),
            &dir,
            ImageBudget::default_for_composite_scan(),
        )
        .await
        .expect_err("a layout that cannot be written is not a layout");
        assert!(
            matches!(refusal, LayoutRefusal::Unwritable(ref msg) if msg.contains("blobs directory")),
            "{refusal:?}"
        );
    }

    /// The two layout files are written last, and a disk that refuses
    /// either one is a refusal: an assembled blob set with no
    /// `index.json` is not something a scanner can read, and is exactly
    /// the shape that must not be left behind. Provoked by occupying the
    /// file's name with a directory, which is the one write failure a
    /// test can arrange without a read-only mount.
    #[tokio::test]
    async fn a_layout_file_that_cannot_be_written_is_refused() {
        for occupied in [OCI_LAYOUT_FILE, INDEX_FILE] {
            let (_tmp, dir) = layout_dir();
            std::fs::create_dir(dir.join(occupied)).expect("occupy the name");
            let refusal = write_image_layout(
                &MapStorage::complete(),
                &two_layer_image(),
                &dir,
                ImageBudget::default_for_composite_scan(),
            )
            .await
            .expect_err("a layout whose own files cannot be written is not a layout");
            assert!(
                matches!(refusal, LayoutRefusal::Unwritable(ref msg) if msg.contains(occupied)),
                "{refusal:?}"
            );
            assert!(
                !dir.exists(),
                "the blobs were already on disk; the refusal must take them with it"
            );
        }
    }

    // -- which side of the retry decision a refusal falls on -------------

    /// Every refusal, on the side it was placed. The table is stated by
    /// value so that moving one is a deliberate edit rather than a drift,
    /// and the direction of a mistake is worth knowing: a transient
    /// condition mis-filed as deterministic shows up only as an image that
    /// never gets assessed.
    #[test]
    fn each_refusal_states_whether_re_running_could_help() {
        // The image declares something hort will not assemble, or a
        // constituent is simply not here. Re-running reads the same facts.
        for deterministic in [
            LayoutRefusal::ConstituentUnreadable {
                which: Constituent::Layer(0),
                hash: hash(LAYER_HASH),
                fault: ConstituentFault::Absent,
                detail: "not present in storage".to_string(),
            },
            LayoutRefusal::TooManyConstituents {
                declared: 900,
                max: 256,
            },
            LayoutRefusal::ByteBudget {
                which: Constituent::Config,
                hash: hash(CONFIG_HASH),
                max: 8,
            },
        ] {
            assert!(
                !deterministic.is_transient(),
                "{deterministic} is about the image, so re-running cannot change it"
            );
        }

        // The machine did not produce the composition.
        for transient in [
            LayoutRefusal::ConstituentUnreadable {
                which: Constituent::Manifest,
                hash: hash(MANIFEST_HASH),
                fault: ConstituentFault::Backend,
                detail: "storage read failed".to_string(),
            },
            LayoutRefusal::TimeBudget { secs: 300 },
            LayoutRefusal::Unwritable("no space left on device".to_string()),
        ] {
            assert!(
                transient.is_transient(),
                "{transient} is about the machine, so re-running may well succeed"
            );
        }
    }

    #[test]
    fn a_constituent_names_its_slot_and_a_layers_position() {
        assert_eq!(Constituent::Manifest.to_string(), "manifest");
        assert_eq!(Constituent::Config.to_string(), "config");
        assert_eq!(Constituent::Layer(0).to_string(), "layers[0]");
        assert_eq!(Constituent::Layer(12).to_string(), "layers[12]");
    }

    #[test]
    fn each_refusal_renders_what_it_refused() {
        assert!(LayoutRefusal::TooManyConstituents {
            declared: 900,
            max: 256
        }
        .to_string()
        .contains("900"));
        assert!(LayoutRefusal::ByteBudget {
            which: Constituent::Config,
            hash: hash(CONFIG_HASH),
            max: 42,
        }
        .to_string()
        .contains("config"));
        assert!(LayoutRefusal::TimeBudget { secs: 300 }
            .to_string()
            .contains("300s"));
        assert!(LayoutRefusal::Unwritable("disk full".to_string())
            .to_string()
            .contains("disk full"));
    }

    /// `NotFound` reads as the plain fact; every other storage error
    /// keeps its own words.
    #[test]
    fn a_read_failure_detail_says_absent_or_quotes_the_backend() {
        assert_eq!(
            read_failure_detail(&DomainError::NotFound {
                entity: "content",
                id: "x".into()
            }),
            "not present in storage"
        );
        assert!(
            read_failure_detail(&DomainError::Invariant("backend said no".to_string()))
                .contains("backend said no")
        );
    }

    /// Cleanup of an already-absent directory is not a failure — the
    /// refusal is the operative fact and a double discard must not
    /// escalate.
    #[tokio::test]
    async fn discarding_an_absent_layout_is_not_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        discard(&tmp.path().join("never-existed")).await;
    }
}
