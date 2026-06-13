//! `FormatHandler` streaming-port helpers (see ADR 0026).
//!
//! The `FormatHandler` body methods (`parse_upstream_checksum`,
//! `extract_upstream_versions`, `extract_dependency_specs`) take a
//! `&mut dyn std::io::Read` rather than a `&[u8]` so the whole upstream
//! body is never buffered at the port boundary. The per-format overrides
//! in `npm.rs` / `cargo.rs` / `pypi.rs` stream the reader through the
//! streaming projectors; these helpers carry the two shared streaming
//! shapes those overrides need:
//!
//! - [`project_with_byte_cap`] — run a [`MetadataProjector`] over the
//!   reader, then enforce the per-format input-size cap (defence-in-depth)
//!   using the EXACT total body length. The cap was a `body.len() > max`
//!   pre-parse check on the old byte-slice path; preserved byte-identically
//!   here (same diagnostic message naming the observed length + cap, never
//!   echoing body bytes). Memory stays bounded by the projection — the
//!   reader is counted, not buffered.
//! - [`read_to_capped_vec`] — read the reader into a `Vec<u8>` bounded by
//!   `max`, returning the canonical over-cap `Validation` error if the
//!   body exceeds it. Used by the format overrides whose parse genuinely
//!   needs the whole body in memory (PyPI's dual HTML/JSON simple-index
//!   walk; the npm/pypi per-version dependency manifests, which are small
//!   and bounded). Matches the old buffered behaviour exactly; the cap is
//!   the same defence-in-depth gate.

use std::io::Read as _;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::{CountingReader, MetadataProjector};

/// Streaming-metadata plausibility ceiling (defence-in-depth) for the
/// `FormatHandler` methods that STREAM the body (never hold it fully in
/// memory). Per the cap taxonomy, a streamed path's cap is a
/// plausibility / downstream-storage bound, NOT the small in-memory
/// ceiling (`metadata_expected_max_bytes`, which is correct only for the
/// BUFFERED `read_to_capped_vec` paths). Aligned with the
/// `HORT_UPSTREAM_METADATA_CACHE_MAX_SIZE` storage backstop default
/// (64 MiB; see ADR 0026 §10.1). The AUTHORITATIVE whole-body bound is
/// that configurable storage backstop enforced at fetch (the tempfile
/// these methods read is already ≤ it); this const is a generous
/// secondary ceiling for any caller that reaches the port without that
/// fetch-time gate. If operators routinely raise the storage backstop
/// above this, raise this in lockstep.
pub(crate) const STREAMING_METADATA_PLAUSIBILITY_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Run `projector` over `reader`, then enforce the per-format input-size
/// cap on the EXACT total body length.
///
/// The reader is wrapped in a [`CountingReader`] so the projection
/// streams (memory-bounded by the projected shape, never the body). After
/// the projector returns, any bytes the projector did not consume (serde
/// stops at the value's closing token) are drained — counted, not
/// buffered — so the cap check sees the true full length and reproduces
/// the old `body.len() > max` diagnostic byte-identically.
///
/// `over_cap` builds the canonical error message from `(observed_len,
/// max)` — each format keeps its own wording (e.g.
/// `"upstream metadata body is {len} bytes; per-format max is {max}"`).
///
/// Order note: the old byte-slice path checked the size cap BEFORE
/// parsing, so an over-cap body always returned the size error regardless
/// of content validity. This helper reproduces "cap wins on an over-cap
/// body" by draining + counting the FULL body on BOTH the projector's
/// success AND error paths, then applying the cap before returning. So:
///
/// - well-formed + over-cap → cap error (matches the old pre-parse gate);
/// - malformed + over-cap → cap error (the projector's parse error is
///   suppressed in favour of the cap error, matching the old gate, which
///   never reached `serde_json` for an over-cap body);
/// - malformed + under-cap → the projector's parse error;
/// - well-formed + under-cap → the projection.
///
/// Memory stays bounded: the projection streams (bounded by its shape),
/// and the drain uses a fixed 8 KiB scratch buffer — the full body is
/// never held.
pub(crate) fn project_with_byte_cap<P, F>(
    reader: &mut dyn std::io::Read,
    max: usize,
    projector: P,
    over_cap: F,
) -> DomainResult<P::Projection>
where
    P: MetadataProjector,
    F: FnOnce(u64, usize) -> String,
{
    let mut counting = CountingReader::new(reader);
    let counter = counting.counter();
    // `&mut CountingReader` is itself `Read`, so the projector borrows the
    // counting reader rather than consuming it — leaving it alive to drain
    // the remainder afterwards on EITHER path.
    let result = projector.project(&mut counting);
    // Drain whatever was left unread (trailing whitespace / bytes after the
    // matched value, OR the rest of the body after an early parse error) so
    // the counter reflects the FULL body length. A drain I/O error is
    // benign here — we only need the byte count for the cap.
    let _ = drain_counting(&mut counting);
    let total = counter.load(std::sync::atomic::Ordering::Relaxed);
    if total > max as u64 {
        return Err(DomainError::Validation(over_cap(total, max)));
    }
    result
}

/// Read the reader to EOF, discarding the bytes (the [`CountingReader`]
/// counts them). Bounded scratch buffer — no full-body allocation.
fn drain_counting<R: std::io::Read>(reader: &mut R) -> DomainResult<()> {
    let mut scratch = [0u8; 8192];
    loop {
        match reader.read(&mut scratch) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                return Err(DomainError::Validation(format!(
                    "failed to drain upstream body: {e}"
                )))
            }
        }
    }
}

/// Read `reader` into a `Vec<u8>` bounded by `max`. Returns the canonical
/// over-cap `Validation` error (built by `over_cap`) the moment the body
/// exceeds `max`, so a pathological body cannot force an unbounded
/// allocation. A body exactly at the cap is accepted (`>` not `>=`,
/// matching the old `body.len() > max` gate).
///
/// Used by the format overrides whose parse needs the whole body in
/// memory anyway (PyPI HTML/JSON simple-index walk; per-version
/// dependency manifests). The cap and acceptance behaviour are identical
/// to the retired buffered path.
pub(crate) fn read_to_capped_vec<F>(
    reader: &mut dyn std::io::Read,
    max: usize,
    over_cap: F,
) -> DomainResult<Vec<u8>>
where
    F: FnOnce(usize, usize) -> String,
{
    // Read up to `max + 1` bytes: if we get `max + 1`, the body is over
    // the cap. `Take` bounds the allocation; we never hold more than
    // `max + 1` bytes. `reader` is `&mut dyn Read` (a Sized reference that
    // itself implements `Read`), so `Read::take` is called on the
    // reference value rather than the unsized trait object.
    let mut buf = Vec::new();
    let mut limited = std::io::Read::take(reader, max as u64 + 1);
    let read = limited
        .read_to_end(&mut buf)
        .map_err(|e| DomainError::Validation(format!("failed to read upstream body: {e}")))?;
    if read > max {
        return Err(DomainError::Validation(over_cap(read, max)));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hort_domain::ports::upstream_proxy::IdentityProjector;
    use std::io::Cursor;

    #[test]
    fn project_with_byte_cap_accepts_body_at_cap() {
        let mut r = Cursor::new(vec![b'x'; 100]);
        let out = project_with_byte_cap(&mut r, 100, IdentityProjector, |_, _| "over".into())
            .expect("at-cap accepted");
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn project_with_byte_cap_rejects_body_over_cap_with_exact_length() {
        let mut r = Cursor::new(vec![b'x'; 101]);
        let err = project_with_byte_cap(&mut r, 100, IdentityProjector, |len, max| {
            format!("body is {len} bytes; max is {max}")
        })
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(ref m)
            if m.contains("101") && m.contains("100")));
    }

    /// A projector that always errors (stand-in for a malformed body).
    #[derive(Clone, Copy)]
    struct AlwaysErrProjector;
    impl MetadataProjector for AlwaysErrProjector {
        type Projection = ();
        fn project<R: std::io::Read>(self, mut r: R) -> DomainResult<()> {
            // Read one byte then bail — mimics serde stopping early on a
            // malformed token while leaving the rest of the body unread.
            let mut one = [0u8; 1];
            let _ = std::io::Read::read(&mut r, &mut one);
            Err(DomainError::Validation("malformed".into()))
        }
    }

    #[test]
    fn project_with_byte_cap_malformed_over_cap_body_yields_cap_error_not_parse_error() {
        // The retired byte-slice gate checked size BEFORE parsing, so an
        // over-cap body always returned the size error regardless of JSON
        // validity. Even when the projector errors early (reading only one
        // byte), draining the rest reveals the over-cap total → the cap
        // error wins. Pins the npm `extract_upstream_versions` over-cap
        // contract (a `vec![b'a'; max+1]` body that is BOTH malformed AND
        // over-cap must reject as Validation, not degrade to empty).
        let mut r = Cursor::new(vec![b'a'; 101]);
        let err = project_with_byte_cap(&mut r, 100, AlwaysErrProjector, |len, max| {
            format!("over: {len} > {max}")
        })
        .unwrap_err();
        assert!(matches!(err, DomainError::Validation(ref m)
            if m.contains("over: 101") && m.contains("100")));
    }

    #[test]
    fn project_with_byte_cap_malformed_under_cap_body_yields_projector_error() {
        // A malformed body UNDER the cap surfaces the projector's own parse
        // error (so the npm versions path can degrade-open on it), NOT a
        // cap error.
        let mut r = Cursor::new(vec![b'a'; 10]);
        let err = project_with_byte_cap(&mut r, 100, AlwaysErrProjector, |_, _| "over".into())
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(ref m) if m == "malformed"));
    }

    #[test]
    fn read_to_capped_vec_accepts_at_cap_rejects_over() {
        let mut r = Cursor::new(vec![b'a'; 50]);
        let v = read_to_capped_vec(&mut r, 50, |_, _| "over".into()).expect("at-cap");
        assert_eq!(v.len(), 50);

        let mut r = Cursor::new(vec![b'a'; 51]);
        let err = read_to_capped_vec(&mut r, 50, |len, max| format!("{len}/{max}")).unwrap_err();
        assert!(matches!(err, DomainError::Validation(ref m) if m.contains("51")));
    }
}
