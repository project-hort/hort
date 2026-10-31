//! What extracting a wheel's `<dist-info>/METADATA` member costs in
//! memory, measured rather than argued.
//!
//! The extraction reads one member — at most a megabyte, capped — out of
//! an archive whose size nothing in the registry bounds. There is no
//! per-format ingest size ceiling, and the inbound `DefaultBodyLimit`
//! that bounds a publish request does not exist on the pull-through
//! path, so "how big is the wheel?" has no answer the extraction can
//! rely on. That makes the relationship between the two the thing worth
//! pinning: the cost of reading the member must not scale with the
//! archive around it.
//!
//! Two tests:
//!
//! - [`seekable_payload_extracts_the_same_metadata_as_a_buffered_one`]
//!   runs always. It proves the seekable path is not merely cheaper but
//!   correct — the same bytes come out either way.
//! - [`peak_occupancy_of_the_extraction_does_not_scale_with_the_wheel`]
//!   is `#[ignore]`d because it writes a 256 MiB fixture and holds half
//!   a gigabyte in one of its arms. Run it deliberately:
//!
//!   ```text
//!   cargo test -p hort-formats --test wheel_metadata_peak_occupancy \
//!       -- --ignored --nocapture
//!   ```
//!
//! The measurement is the kernel's own `VmHWM` ("peak resident set
//! size", `/proc/self/status`) sampled around each arm, not an
//! allocation count and not a derivation from the code. `VmHWM` is a
//! high-water mark and never decreases, so the arms run cheapest-first
//! and each one's cost is the rise it causes.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hort_domain::entities::repository::RepositoryFormat;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::types::{ArtifactCoords, PayloadAccess};
use hort_formats::pypi::PyPiFormatHandler;

/// The `<dist-info>/METADATA` body every fixture carries.
const METADATA_BODY: &[u8] =
    b"Metadata-Version: 2.1\nName: bigwheel\nVersion: 1.0.0\nRequires-Dist: urllib3\n";

/// Payload bytes the measurement fixture pads the wheel out to. 256 MiB
/// is below what the publish route already admits (300 MiB) and well
/// below what a pull-through ingest can be handed, so it is a
/// conservative stand-in rather than a worst case.
const MEASUREMENT_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A wheel fixture on disk, removed when the guard drops — including on
/// a panicking assertion, which is why it is a guard and not a pair of
/// statements around the test body.
struct WheelFixture {
    path: PathBuf,
}

impl Drop for WheelFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Write a PEP 427-shaped wheel to a unique path under the temp dir: one
/// `STORED` payload member of `payload_bytes`, then the `METADATA`
/// member the extractor is after.
///
/// `STORED` rather than deflated so the file on disk is the size asked
/// for (deflate would squeeze a run of zeros to nothing and measure
/// nothing), and written in 1 MiB chunks so building the fixture does not
/// itself hold the wheel in memory.
///
/// METADATA is written **last**, which is both what real wheel builders
/// do and the layout that makes the point: a front-to-back reader has to
/// cross the whole payload to reach it, while a central-directory read
/// seeks straight to it.
fn write_wheel(tag: &str, payload_bytes: usize) -> WheelFixture {
    let path =
        std::env::temp_dir().join(format!("hort-wheel-peak-{}-{tag}.whl", std::process::id()));
    let fixture = WheelFixture { path };

    let file = std::fs::File::create(&fixture.path).expect("create wheel fixture");
    let mut zip = zip::ZipWriter::new(file);
    let stored =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    zip.start_file("bigwheel/payload.bin", stored)
        .expect("start payload member");
    let chunk = vec![0u8; 1024 * 1024];
    let mut written = 0usize;
    while written < payload_bytes {
        let n = chunk.len().min(payload_bytes - written);
        zip.write_all(&chunk[..n]).expect("write payload chunk");
        written += n;
    }

    zip.start_file("bigwheel-1.0.0.dist-info/METADATA", stored)
        .expect("start METADATA member");
    zip.write_all(METADATA_BODY).expect("write METADATA");
    zip.finish().expect("finish wheel fixture");

    fixture
}

fn wheel_coords() -> ArtifactCoords {
    ArtifactCoords {
        name: "bigwheel".into(),
        name_as_published: "bigwheel".into(),
        version: Some("1.0.0".into()),
        path: "simple/bigwheel/bigwheel-1.0.0-py3-none-any.whl".into(),
        format: RepositoryFormat::Pypi,
        metadata: serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Peak-RSS probe
// ---------------------------------------------------------------------------

/// Peak resident set size of this process in bytes, from `VmHWM`.
///
/// The kernel maintains this high-water mark, so there is no sampling
/// race: a buffer that was briefly resident is still counted after it is
/// freed, which is exactly the "what did this cost at its worst?"
/// question. Returns `None` where `/proc` does not carry the field, so
/// the measurement declines rather than inventing a number.
fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())?;
            return Some(kb * 1024);
        }
    }
    None
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

// ---------------------------------------------------------------------------
// Correctness: the seekable path answers the same as the buffered one
// ---------------------------------------------------------------------------

#[test]
fn seekable_payload_extracts_the_same_metadata_as_a_buffered_one() {
    let fixture = write_wheel("equiv", 2 * 1024 * 1024);
    let handler = PyPiFormatHandler;
    let coords = wheel_coords();

    let mut file = std::fs::File::open(&fixture.path).expect("open fixture");
    let from_seek = handler
        .extract_wheel_metadata_bytes(
            &coords,
            PayloadAccess::ReadSeek(Box::new(file.try_clone().expect("clone handle"))),
        )
        .expect("seekable extraction")
        .expect("METADATA member present");

    file.seek(SeekFrom::Start(0)).expect("rewind");
    let mut buffered = Vec::new();
    file.read_to_end(&mut buffered).expect("read fixture");
    let from_bytes = handler
        .extract_wheel_metadata_bytes(&coords, PayloadAccess::Bytes(&buffered))
        .expect("buffered extraction")
        .expect("METADATA member present");

    assert_eq!(
        from_seek, from_bytes,
        "the seekable and buffered payload paths must agree byte for byte"
    );
    assert_eq!(
        from_seek.as_ref(),
        METADATA_BODY,
        "extracted METADATA must be the member that was written"
    );
}

/// A handle handed over at the wrong offset must not change the answer.
///
/// This is the failure mode a seekable payload invites, and it is a
/// quiet one: the PEP 658 path reads "no central directory" as the
/// ordinary non-fatal "this wheel advertises nothing", so a caller who
/// forgot to rewind would get silent loss of metadata rather than an
/// error. The loss does not happen, and the reason is worth knowing
/// before relying on it — `ZipArchive` locates the central directory by
/// seeking from the **end** of the stream, not from wherever the handle
/// happens to be. Pinned here so a future reader does not have to take
/// that on trust, and so a change in the archive reader that made the
/// incoming position matter shows up as a failure here rather than as
/// wheels that quietly stop advertising.
#[test]
fn a_payload_handle_left_at_eof_still_finds_the_metadata_member() {
    let fixture = write_wheel("eof", 1024);
    let handler = PyPiFormatHandler;
    let mut file = std::fs::File::open(&fixture.path).expect("open fixture");
    let end = file.seek(SeekFrom::End(0)).expect("seek to EOF");
    assert!(
        end > 0,
        "the fixture must have length for the seek to mean anything"
    );

    let out = handler
        .extract_wheel_metadata_bytes(&wheel_coords(), PayloadAccess::ReadSeek(Box::new(file)))
        .expect("extraction")
        .expect("METADATA is found from a central-directory read regardless of position");
    assert_eq!(out.as_ref(), METADATA_BODY);
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

/// Extract METADATA from a 256 MiB wheel three ways and report what each
/// costs in peak resident memory.
///
/// The arms, cheapest first (`VmHWM` only rises, so order matters):
///
/// 1. **seekable** — what the production callers now do: a file handle,
///    `PayloadAccess::ReadSeek`, central directory then one member.
/// 2. **one whole buffer** — the app layer's `read_to_end` into a
///    `Vec<u8>`, handed over as `PayloadAccess::Bytes`.
/// 3. **two whole buffers** — arm 2 plus a second live copy, which is
///    what the code held before this change: the app layer buffered the
///    wheel and the handler's `Bytes` arm then did `b.to_vec()` on it,
///    so both were alive across the walk. The `clone()` here stands in
///    for that deleted line; nothing in the handler copies any more.
///
/// The assertion is the relationship, not an absolute: arm 1 must cost a
/// small fraction of the archive, and arm 3 must cost more than one copy
/// of it. Thresholds are deliberately slack — the point is the shape of
/// the scaling, and a tight bound on RSS would be a flaky test.
#[test]
#[ignore = "writes a 256 MiB fixture and peaks ~0.5 GiB; run deliberately with --ignored --nocapture"]
fn peak_occupancy_of_the_extraction_does_not_scale_with_the_wheel() {
    let Some(baseline) = peak_rss_bytes() else {
        eprintln!("VmHWM unavailable on this platform; measurement declined");
        return;
    };
    let fixture = write_wheel("measure", MEASUREMENT_PAYLOAD_BYTES);
    let wheel_size = std::fs::metadata(&fixture.path)
        .expect("stat fixture")
        .len();
    let after_fixture = peak_rss_bytes().expect("VmHWM");

    let handler = PyPiFormatHandler;
    let coords = wheel_coords();

    // --- arm 1: seekable ---------------------------------------------
    let file = std::fs::File::open(&fixture.path).expect("open fixture");
    let seek_out = handler
        .extract_wheel_metadata_bytes(&coords, PayloadAccess::ReadSeek(Box::new(file)))
        .expect("seekable extraction")
        .expect("METADATA present");
    assert_eq!(seek_out.as_ref(), METADATA_BODY);
    let after_seek = peak_rss_bytes().expect("VmHWM");

    // --- arm 2: one whole buffer -------------------------------------
    let one_buffer_peak = {
        let buf = std::fs::read(&fixture.path).expect("read fixture whole");
        let out = handler
            .extract_wheel_metadata_bytes(&coords, PayloadAccess::Bytes(&buf))
            .expect("buffered extraction")
            .expect("METADATA present");
        assert_eq!(out.as_ref(), METADATA_BODY);
        peak_rss_bytes().expect("VmHWM")
    };

    // --- arm 3: two whole buffers (the pre-change shape) -------------
    let two_buffer_peak = {
        let outer = std::fs::read(&fixture.path).expect("read fixture whole");
        let inner = outer.clone();
        let out = handler
            .extract_wheel_metadata_bytes(&coords, PayloadAccess::Bytes(&inner))
            .expect("buffered extraction")
            .expect("METADATA present");
        assert_eq!(out.as_ref(), METADATA_BODY);
        // Both buffers must still be alive at the sample, or the arm
        // measures arm 2 over again.
        assert_eq!(outer.len(), inner.len());
        peak_rss_bytes().expect("VmHWM")
    };

    let seek_cost = after_seek.saturating_sub(after_fixture);
    let one_cost = one_buffer_peak.saturating_sub(after_seek);
    let two_cost = two_buffer_peak.saturating_sub(one_buffer_peak) + one_cost;

    println!("wheel on disk                : {:.1} MiB", mib(wheel_size));
    println!("baseline VmHWM               : {:.1} MiB", mib(baseline));
    println!(
        "VmHWM after fixture build    : {:.1} MiB",
        mib(after_fixture)
    );
    println!(
        "arm 1 seekable        VmHWM  : {:.1} MiB  (+{:.1} MiB)",
        mib(after_seek),
        mib(seek_cost)
    );
    println!(
        "arm 2 one buffer      VmHWM  : {:.1} MiB  (+{:.1} MiB)",
        mib(one_buffer_peak),
        mib(one_cost)
    );
    println!(
        "arm 3 two buffers     VmHWM  : {:.1} MiB  (+{:.1} MiB cumulative)",
        mib(two_buffer_peak),
        mib(two_cost)
    );

    assert!(
        seek_cost * 8 < wheel_size,
        "the seekable extraction must not scale with the archive: it cost {:.1} MiB \
         against a {:.1} MiB wheel",
        mib(seek_cost),
        mib(wheel_size)
    );
    assert!(
        two_cost > wheel_size,
        "the pre-change shape held more than one whole copy of the wheel; measured \
         {:.1} MiB against a {:.1} MiB wheel",
        mib(two_cost),
        mib(wheel_size)
    );
}

/// `write_wheel` is the measurement's premise, so it gets its own check:
/// a `STORED` payload member means the file on disk really is the size
/// asked for. A deflated fixture would compress a run of zeros to
/// nothing and the measurement would be of a small file wearing a big
/// number.
#[test]
fn the_fixture_is_really_as_large_as_it_claims() {
    let fixture = write_wheel("size", 4 * 1024 * 1024);
    let on_disk = std::fs::metadata(&fixture.path).expect("stat").len();
    assert!(
        on_disk >= 4 * 1024 * 1024,
        "fixture must not be compressed away: {on_disk} bytes on disk for a 4 MiB payload"
    );
}

/// Guard for the guard: the fixture file is gone once its owner drops,
/// so a measurement run leaves nothing behind in the temp dir.
#[test]
fn the_fixture_is_removed_when_its_guard_drops() {
    let path: PathBuf = {
        let fixture = write_wheel("cleanup", 1024);
        assert!(
            Path::new(&fixture.path).exists(),
            "fixture must exist while held"
        );
        fixture.path.clone()
    };
    assert!(
        !path.exists(),
        "fixture must be removed when the guard drops"
    );
}
