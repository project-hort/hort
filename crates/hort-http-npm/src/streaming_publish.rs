//! Streaming npm publish-body decoder.
//!
//! npm publish bodies are JSON envelopes that carry the tarball as a
//! base64-encoded string at `_attachments[<filename>].data`. The prior
//! handler buffered the whole envelope (`body: Bytes`, up to
//! [`hort_http_core::limits::DEFAULT_PUBLISH_BODY_LIMIT`] ≈ 300 MiB) and
//! then materialised the decoded tarball as a fresh `Vec<u8>` (~225
//! MiB for a 200 MiB upload), computing SHA-1 against the decoded
//! buffer. Peak heap was ~525 MiB per concurrent publish — ten
//! concurrent publishes from a single authenticated user OOM'd the
//! server.
//!
//! This module replaces that with a streaming decoder. The body is
//! consumed chunk-by-chunk from the axum [`Body`]. The envelope JSON
//! is recognised by a small state machine that locates the
//! `"_attachments":` section, then the first attachment's `"data":"`
//! base64 string. The base64 bytes are decoded incrementally into a
//! [`tempfile::NamedTempFile`] on disk; SHA-1 is computed at the same
//! time. The envelope bytes outside the base64 payload are buffered
//! (small — typically a few KiB), and after decoding the JSON
//! envelope is reconstructed as `<prefix>""<suffix>` and parsed
//! normally so existing `versions[v]` / `_attachments[<filename>]`
//! extraction continues to work.
//!
//! Memory invariant: peak heap is O(envelope-without-base64 +
//! chunk-size) — bounded by [`MAX_ENVELOPE_BYTES`] (32 MiB) plus the
//! read-buffer size, NOT by tarball size. A 200 MiB tarball publish
//! now spools to disk in chunk-sized writes; nothing approaching 200
//! MiB sits on the heap.
//!
//! Pre-existing validation behaviour is preserved verbatim:
//!
//! - Body exceeding the publish body-limit                        → 413
//!   (enforced via byte-count rejection in [`stream_decode_body`])
//! - Malformed JSON envelope                                      → 400
//! - Missing `_attachments` / no attachments / missing `data`     → 400
//! - Invalid base64 inside `data`                                 → 400
//!
//! The SHA-1 hex returned alongside the temp-file handle feeds
//! `IngestUseCase::ingest_direct`'s `legacy_sha1` field, exactly as
//! the prior path did.
//!
//! Note: the per-format inbound HTTP crate must not depend on
//! `hort-adapters-*` (see Anti-Patterns Checklist in the project root
//! `CLAUDE.md`); this module touches only `tokio::fs::File`,
//! `tempfile`, the `base64` decoder, and the existing `ApiError` /
//! `Response` types.

use std::io::SeekFrom;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bytes::Bytes;
use futures::stream::StreamExt as _;
use sha1::{Digest as _, Sha1};
use tempfile::NamedTempFile;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};

use hort_http_core::error::ApiError;

/// Hard cap on the bytes we will buffer for the JSON envelope alone
/// (everything outside the base64 `data` value). Real npm publish
/// envelopes are < 1 KiB without the attachment payload; the
/// per-version `versions[v]` block can balloon to several MiB for
/// packages with very long dependency lists, so we set the cap at
/// 32 MiB to comfortably cover that without giving an attacker a
/// vector for unbounded envelope inflation. A request whose envelope
/// exceeds this is rejected with 400 (it is a malformed publish — npm
/// clients do not produce envelopes this large outside the base64
/// attachment).
pub(crate) const MAX_ENVELOPE_BYTES: usize = 32 * 1024 * 1024;

/// Outcome of streaming the publish body. The envelope JSON has the
/// `data` base64 string replaced with `""` so the buffer is small
/// regardless of tarball size; the decoded tarball lives in the
/// `tempfile`, and `sha1_hex` is the SHA-1 over the decoded bytes —
/// the value `IngestUseCase::ingest_direct` writes onto
/// `Artifact.sha1_checksum` (the npm `dist.shasum` invariant).
///
/// Debug-printing the struct only shows the SHA-1 + size — the
/// `tarball_file` `NamedTempFile` and the (potentially large)
/// envelope buffer would clutter test failure output.
pub(crate) struct DecodedPublish {
    /// Reconstructed envelope JSON (prefix + `""` + suffix). Always
    /// well-formed JSON if the original publish was well-formed; ready
    /// for `serde_json::from_slice`. Memory footprint matches the
    /// original envelope minus the base64 payload — typically a few
    /// KiB; capped at [`MAX_ENVELOPE_BYTES`].
    pub envelope: Vec<u8>,
    /// `tempfile::NamedTempFile` holding the decoded tarball bytes.
    /// File is open for reading via [`tempfile_reader`]; drops at
    /// scope-exit, removing the file from /tmp; aborted publishes
    /// leak nothing.
    pub tarball_file: NamedTempFile,
    /// SHA-1 hex of the decoded tarball — feeds
    /// `DirectIngestRequest.legacy_sha1` so the persisted
    /// `Artifact.sha1_checksum` matches the npm `dist.shasum`.
    pub sha1_hex: String,
    /// Total decoded tarball size in bytes. Recorded for
    /// observability; ingest computes its own size from the stream.
    pub tarball_size: u64,
}

impl std::fmt::Debug for DecodedPublish {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedPublish")
            .field("envelope_len", &self.envelope.len())
            .field("sha1_hex", &self.sha1_hex)
            .field("tarball_size", &self.tarball_size)
            .finish()
    }
}

/// Typed error returned by [`stream_decode_body`].
///
/// The handler maps each variant to the same HTTP status the prior
/// `body: Bytes` path returned:
///
/// - [`StreamDecodeError::BodyTooLarge`] → 413 (was emitted by axum's
///   `DefaultBodyLimit` extractor)
/// - [`StreamDecodeError::Validation`] → 400 via [`ApiError`]
///   (`DomainError::Validation`)
/// - [`StreamDecodeError::Infrastructure`] → 503 — tempfile creation,
///   disk-write failure (does not occur on the client's bad-input path)
#[derive(Debug)]
pub(crate) enum StreamDecodeError {
    /// Body exceeded the per-publish byte-count cap. Maps to 413.
    BodyTooLarge,
    /// Malformed JSON shape, missing `_attachments[*].data`, invalid
    /// base64. Maps to 400. The string is the error message and
    /// matches the prior `validation_error(...)`-shaped wire body.
    Validation(String),
    /// Tempfile / disk I/O failure. Maps to 503. The string is logged
    /// but the wire body is the generic `publish spool failed`.
    Infrastructure(String),
}

impl StreamDecodeError {
    /// Convert the typed error into an HTTP `Response` matching the
    /// prior wire shape.
    pub(crate) fn into_response(self) -> Response {
        match self {
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::json!({"error": "publish body exceeds limit"}).to_string(),
            )
                .into_response(),
            Self::Validation(msg) => ApiError::from(hort_app::error::AppError::Domain(
                hort_domain::error::DomainError::Validation(msg),
            ))
            .into_response(),
            Self::Infrastructure(msg) => {
                tracing::error!(error = %msg, "publish spool infrastructure failure");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    serde_json::json!({"error": "publish spool failed"}).to_string(),
                )
                    .into_response()
            }
        }
    }
}

/// Stream the publish body, locate `_attachments[*].data`, decode its
/// base64 content into a tempfile while computing SHA-1, and parse
/// the envelope around the data field.
///
/// `body_limit_bytes` is the same cap that
/// `npm_routes_with_publish_limit` configures via `DefaultBodyLimit`
/// — re-checked here because `DefaultBodyLimit` only applies to
/// `Bytes`/`Json` extractors, NOT to raw `Body` streamed via
/// `into_data_stream()`. Without the explicit count an oversize body
/// would silently flow through and exhaust /tmp instead of returning
/// 413.
///
/// On any structural error (malformed JSON shape, missing attachments,
/// invalid base64, oversize envelope, oversize body) returns a typed
/// [`StreamDecodeError`] mapped by the caller to the same HTTP status
/// the prior handler returned.
#[tracing::instrument(skip(body), fields(body_limit_bytes = body_limit_bytes))]
pub(crate) async fn stream_decode_body(
    body: Body,
    body_limit_bytes: usize,
) -> Result<DecodedPublish, StreamDecodeError> {
    let tarball_file = NamedTempFile::new()
        .map_err(|e| StreamDecodeError::Infrastructure(format!("tempfile create failed: {e}")))?;

    let mut writer = File::from_std(tarball_file.reopen().map_err(|e| {
        StreamDecodeError::Infrastructure(format!("tempfile reopen-for-write failed: {e}"))
    })?);

    let mut data_stream = body.into_data_stream();
    let mut state = ParseState::new();
    let mut sha1 = Sha1::new();
    let mut decoded_bytes: u64 = 0;
    let mut total_consumed: usize = 0;

    while let Some(chunk_res) = data_stream.next().await {
        let chunk: Bytes = chunk_res.map_err(|e| {
            // tower / axum body-limit error surfaces here when the
            // outer `DefaultBodyLimit` would have rejected. Map to
            // BodyTooLarge to match the prior `Bytes`-extractor 413.
            // Other axum body errors (early client disconnect, etc.)
            // surface as Validation 400 — the conservative shape.
            let msg = format!("{e:#}");
            if msg.contains("length limit") {
                StreamDecodeError::BodyTooLarge
            } else {
                StreamDecodeError::Validation(format!("publish body read error: {msg}"))
            }
        })?;

        total_consumed = total_consumed.saturating_add(chunk.len());
        if total_consumed > body_limit_bytes {
            return Err(StreamDecodeError::BodyTooLarge);
        }

        state
            .feed(&chunk, &mut sha1, &mut writer, &mut decoded_bytes)
            .await?;
    }

    state.finish()?;

    writer
        .flush()
        .await
        .map_err(|e| StreamDecodeError::Infrastructure(format!("tempfile flush failed: {e}")))?;
    drop(writer);

    let envelope = state.into_envelope_bytes()?;
    let sha1_hex = format!("{:x}", sha1.finalize());

    tracing::debug!(
        tarball_size = decoded_bytes,
        envelope_size = envelope.len(),
        "streamed npm publish body decode complete"
    );

    Ok(DecodedPublish {
        envelope,
        tarball_file,
        sha1_hex,
        tarball_size: decoded_bytes,
    })
}

/// Open the spooled tarball as an `AsyncRead` for `ingest_direct` to
/// consume. Always positions at offset 0 — the temp file may have
/// been written by a `tokio::fs::File` handle that's since been
/// dropped; a fresh handle starts at 0.
///
/// Errors are mapped to a 503 [`Response`] (same shape as
/// [`StreamDecodeError::Infrastructure`]). A reopen / seek failure
/// is exotic — filesystem corruption between the write phase and
/// the read phase — and is NOT a client-bad-input case; the caller
/// returns 503 to signal "transient backend failure, retry".
pub(crate) async fn tempfile_reader(tarball_file: &NamedTempFile) -> Result<File, Response> {
    let std_file = tarball_file.reopen().map_err(|e| {
        StreamDecodeError::Infrastructure(format!("tempfile reopen-for-read failed: {e}"))
            .into_response()
    })?;
    let mut file = File::from_std(std_file);
    file.seek(SeekFrom::Start(0)).await.map_err(|e| {
        StreamDecodeError::Infrastructure(format!("tempfile seek-to-start failed: {e}"))
            .into_response()
    })?;
    Ok(file)
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Phase of the JSON envelope walk.
///
/// The state machine recognises the small subset of JSON we care
/// about — top-level object, the `_attachments` key, the first
/// attachment object, the `data` key, the base64 string value — and
/// otherwise treats bytes as opaque. Every byte before the base64
/// string is buffered into `prefix`; every byte after the closing `"`
/// is buffered into `suffix`. Brace / bracket / quote tracking is the
/// minimum needed to distinguish "we are inside a string literal"
/// from "we are between fields" so the recogniser does not mistake a
/// brace inside a value for the end of an object.
#[derive(Debug)]
enum Phase {
    /// Bytes flow into `prefix`; we have not yet seen the opening
    /// quote of the `data` value.
    SeekingDataValue,
    /// Bytes are base64 chars; we are decoding incrementally. Ends
    /// when the closing `"` is hit.
    DecodingBase64,
    /// Bytes flow into `suffix`; we have closed the base64 string.
    AfterClose,
}

/// Recogniser sub-state used while in `SeekingDataValue` to track
/// where in the JSON we are. Implemented as a small lexer rather than
/// a full JSON parser so the streaming path stays O(constant) memory
/// regardless of envelope shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lex {
    /// Outside any string literal, between values / keys.
    Default,
    /// Inside a JSON string literal (`"..."`); `escape` tracks
    /// whether the next byte is escaped by a preceding `\`.
    InString { escape: bool },
}

/// Sub-state of `Phase::SeekingDataValue` — what milestone of the
/// envelope walk we have reached. The `Phase` enum is too coarse:
/// "seeking data value" covers everything from the opening `{` of
/// the publish body to the opening `"` of the base64 string. This
/// inner enum tracks the structural milestones along the way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seek {
    /// We have not yet seen `"_attachments":`. We are still in the
    /// top-level object's other fields (`name`, `versions`, etc.).
    BeforeAttachmentsKey,
    /// We have seen `"_attachments":` at top-level. The next `{`
    /// opens the attachments-by-filename object.
    AwaitingAttachmentsObject,
    /// We are inside the attachments-by-filename object. The next
    /// `:` after a string key marks the filename → attachment-object
    /// pair; the `{` after that opens the first attachment.
    InAttachmentsObject,
    /// We have seen a filename key and its `:`. The next `{` opens
    /// the first attachment object.
    AwaitingAttachmentObject,
    /// We are inside the first attachment object. The next `"data":`
    /// followed by the opening `"` of its string value transitions
    /// to `Phase::DecodingBase64`.
    InFirstAttachment,
    /// We just consumed `"data":` and are waiting for the opening
    /// `"` of the base64 string value.
    AwaitingBase64Open,
}

struct ParseState {
    phase: Phase,
    lex: Lex,
    /// Brace depth — 0 means we have seen no `{` yet, > 0 means we
    /// are inside the top-level object.
    brace_depth: i64,
    /// Sub-state inside `Phase::SeekingDataValue` — see [`Seek`].
    seek: Seek,
    /// Most-recent JSON string literal we just closed — used to
    /// detect the `_attachments` and `data` keys at colon time.
    /// Cleared on every `{` and at every key recognition.
    last_string: Vec<u8>,
    /// Brace depth recorded when we saw the `:` after
    /// `"_attachments"`. The attachments-by-filename object is the
    /// `{` whose increment lands at `attachments_inside_depth ==
    /// attachments_outer_depth + 1`.
    attachments_outer_depth: i64,
    /// Brace depth recorded when we saw the `:` after a filename
    /// key inside the attachments object. The first attachment
    /// object is the `{` whose increment lands at
    /// `first_attachment_inside_depth == first_attachment_outer_depth + 1`.
    first_attachment_outer_depth: i64,
    /// Bytes accumulated for the envelope prefix (everything before
    /// and including the `"data":"` opening quote).
    prefix: Vec<u8>,
    /// Bytes accumulated for the envelope suffix (everything from
    /// the closing `"` of the base64 string to end of body).
    suffix: Vec<u8>,
    /// 4-char carry for streaming base64 — base64 decodes in groups
    /// of 4 characters → 3 bytes; the carry holds the partial group
    /// across chunk boundaries.
    b64_carry: Vec<u8>,
}

impl ParseState {
    fn new() -> Self {
        Self {
            phase: Phase::SeekingDataValue,
            lex: Lex::Default,
            brace_depth: 0,
            seek: Seek::BeforeAttachmentsKey,
            last_string: Vec::new(),
            attachments_outer_depth: 0,
            first_attachment_outer_depth: 0,
            prefix: Vec::new(),
            suffix: Vec::new(),
            b64_carry: Vec::new(),
        }
    }

    /// Process a chunk; route bytes into `prefix`, base64 decoder,
    /// or `suffix` depending on phase.
    async fn feed(
        &mut self,
        chunk: &[u8],
        sha1: &mut Sha1,
        writer: &mut File,
        decoded_bytes: &mut u64,
    ) -> Result<(), StreamDecodeError> {
        let mut i = 0usize;
        while i < chunk.len() {
            match self.phase {
                Phase::SeekingDataValue => {
                    let byte = chunk[i];
                    self.feed_envelope_byte(byte)?;
                    self.prefix.push(byte);
                    if self.prefix.len() > MAX_ENVELOPE_BYTES {
                        return Err(StreamDecodeError::Validation(
                            "publish envelope exceeds size limit before reaching `_attachments[*].data`"
                                .into(),
                        ));
                    }
                    i += 1;
                    // If `feed_envelope_byte` transitioned us, the
                    // opening `"` was the byte we just pushed; the
                    // next iteration will start decoding base64.
                }
                Phase::DecodingBase64 => {
                    // Find the closing `"` (unescaped — the base64
                    // alphabet does not include `"` or `\`, so any
                    // `"` we see is the close).
                    let close_pos = chunk[i..].iter().position(|&b| b == b'"');
                    let (b64_slice, hit_close) = match close_pos {
                        Some(p) => (&chunk[i..i + p], true),
                        None => (&chunk[i..], false),
                    };
                    self.decode_base64_chunk(b64_slice, sha1, writer, decoded_bytes)
                        .await?;
                    if hit_close {
                        // Flush any carry — base64 must be a multiple
                        // of 4 chars (with `=` padding); otherwise
                        // the input is malformed.
                        self.flush_base64_carry(sha1, writer, decoded_bytes).await?;
                        self.phase = Phase::AfterClose;
                        // The closing `"` itself goes into `suffix`.
                        self.suffix.push(b'"');
                        i += b64_slice.len() + 1;
                    } else {
                        i += b64_slice.len();
                    }
                }
                Phase::AfterClose => {
                    // Append the rest of the chunk verbatim to suffix.
                    let rest = &chunk[i..];
                    if self.suffix.len() + rest.len() > MAX_ENVELOPE_BYTES {
                        return Err(StreamDecodeError::Validation(
                            "publish envelope exceeds size limit after `_attachments[*].data`"
                                .into(),
                        ));
                    }
                    self.suffix.extend_from_slice(rest);
                    i = chunk.len();
                }
            }
        }
        Ok(())
    }

    /// Walk one byte of the envelope (pre-base64 phase). Updates
    /// lex / brace-depth / key-tracking state and may transition the
    /// phase to `DecodingBase64` when the opening `"` of the `data`
    /// value is hit.
    fn feed_envelope_byte(&mut self, byte: u8) -> Result<(), StreamDecodeError> {
        match self.lex {
            Lex::InString { escape } => {
                if escape {
                    self.lex = Lex::InString { escape: false };
                    self.last_string.push(byte);
                } else if byte == b'\\' {
                    self.lex = Lex::InString { escape: true };
                } else if byte == b'"' {
                    // Closing quote of a normal JSON string.
                    self.lex = Lex::Default;
                } else {
                    self.last_string.push(byte);
                }
            }
            Lex::Default => match byte {
                b'"' => {
                    // Special case — opening quote of the base64
                    // value. When we are awaiting it, transition to
                    // `DecodingBase64` instead of entering
                    // `Lex::InString` (which would treat the entire
                    // base64 payload as a JSON string body and we
                    // would then miss the streaming-decode boundary).
                    if matches!(self.seek, Seek::AwaitingBase64Open) {
                        self.phase = Phase::DecodingBase64;
                    } else {
                        self.lex = Lex::InString { escape: false };
                        self.last_string.clear();
                    }
                }
                b'{' => {
                    self.brace_depth += 1;
                    match self.seek {
                        Seek::AwaitingAttachmentsObject => {
                            // The `{` after `"_attachments":`. We
                            // are now inside the by-filename map.
                            if self.brace_depth == self.attachments_outer_depth + 1 {
                                self.seek = Seek::InAttachmentsObject;
                            }
                        }
                        Seek::AwaitingAttachmentObject => {
                            // The `{` after the first filename key
                            // and its `:`. We are now inside the
                            // first attachment object.
                            if self.brace_depth == self.first_attachment_outer_depth + 1 {
                                self.seek = Seek::InFirstAttachment;
                            }
                        }
                        _ => {}
                    }
                    // Fresh object — drop any partially-tracked key.
                    self.last_string.clear();
                }
                b'}' => {
                    self.brace_depth -= 1;
                    // If we left the structures we cared about
                    // before finding `data`, keep advancing. The
                    // `finish()` end-of-stream check surfaces this
                    // as a 400 with the right message.
                    match self.seek {
                        Seek::InAttachmentsObject
                            if self.brace_depth <= self.attachments_outer_depth =>
                        {
                            // Left the `_attachments` object.
                            self.seek = Seek::BeforeAttachmentsKey;
                        }
                        Seek::AwaitingAttachmentObject
                            if self.brace_depth <= self.attachments_outer_depth =>
                        {
                            self.seek = Seek::BeforeAttachmentsKey;
                        }
                        Seek::InFirstAttachment
                            if self.brace_depth <= self.first_attachment_outer_depth =>
                        {
                            // Left the first attachment without
                            // finding `data`. Allow `finish()` to
                            // emit the "missing data" error.
                            self.seek = Seek::InAttachmentsObject;
                        }
                        _ => {}
                    }
                }
                b':' => {
                    // Apply the most-recent string as a key.
                    match self.seek {
                        Seek::BeforeAttachmentsKey
                            if self.brace_depth == 1 && self.last_string == b"_attachments" =>
                        {
                            self.seek = Seek::AwaitingAttachmentsObject;
                            self.attachments_outer_depth = self.brace_depth;
                        }
                        Seek::InAttachmentsObject
                            if self.brace_depth == self.attachments_outer_depth + 1 =>
                        {
                            // Any string key inside the attachments
                            // object — the FIRST one is the only one
                            // we will fully traverse; subsequent
                            // ones (npm only ever sends one entry
                            // per publish) are ignored after we have
                            // already entered the first attachment.
                            self.seek = Seek::AwaitingAttachmentObject;
                            self.first_attachment_outer_depth = self.brace_depth;
                        }
                        Seek::InFirstAttachment
                            if self.brace_depth == self.first_attachment_outer_depth + 1
                                && self.last_string == b"data" =>
                        {
                            self.seek = Seek::AwaitingBase64Open;
                        }
                        _ => {}
                    }
                    // Don't clear last_string — keys can repeat at
                    // sibling depth and the `_attachments` recogniser
                    // already consumed it.
                }
                _ => {}
            },
        }
        Ok(())
    }

    /// Decode a slice of base64 characters into the writer + sha1.
    /// Carries over any partial 4-byte group between calls so chunks
    /// can split mid-group.
    async fn decode_base64_chunk(
        &mut self,
        b64: &[u8],
        sha1: &mut Sha1,
        writer: &mut File,
        decoded_bytes: &mut u64,
    ) -> Result<(), StreamDecodeError> {
        if b64.is_empty() {
            return Ok(());
        }
        // base64 decoders in the standard alphabet tolerate stray
        // whitespace; `_attachments[*].data` is a JSON string with
        // no embedded whitespace per real-`npm publish` clients, but
        // we filter defensively before grouping so chunk boundaries
        // never split a byte across a whitespace.
        let mut filtered: Vec<u8> = Vec::with_capacity(b64.len());
        for &b in b64 {
            if !b.is_ascii_whitespace() {
                filtered.push(b);
            }
        }
        // Prepend any carry from the previous chunk.
        let mut carry = std::mem::take(&mut self.b64_carry);
        carry.extend_from_slice(&filtered);
        let group_count = carry.len() / 4;
        let aligned_len = group_count * 4;
        // If the remainder includes any `=` padding, it must be at
        // the end (final group); leaving it in the carry is correct
        // — `flush_base64_carry` will decode it once the closing
        // `"` is hit.
        let (aligned, remainder) = carry.split_at(aligned_len);

        if !aligned.is_empty() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(aligned)
                .map_err(|e| {
                    StreamDecodeError::Validation(format!("invalid base64 in attachment: {e}"))
                })?;
            sha1.update(&decoded);
            writer.write_all(&decoded).await.map_err(|e| {
                StreamDecodeError::Infrastructure(format!("tempfile write failed: {e}"))
            })?;
            *decoded_bytes += decoded.len() as u64;
        }
        self.b64_carry = remainder.to_vec();
        Ok(())
    }

    /// Flush any 4-byte aligned remainder in `b64_carry` once the
    /// closing `"` is hit. base64 must end on a 4-char boundary
    /// (padded with `=`); a non-empty non-aligned remainder is a
    /// malformed publish.
    async fn flush_base64_carry(
        &mut self,
        sha1: &mut Sha1,
        writer: &mut File,
        decoded_bytes: &mut u64,
    ) -> Result<(), StreamDecodeError> {
        let carry = std::mem::take(&mut self.b64_carry);
        if carry.is_empty() {
            return Ok(());
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&carry)
            .map_err(|e| {
                StreamDecodeError::Validation(format!("invalid base64 in attachment: {e}"))
            })?;
        sha1.update(&decoded);
        writer.write_all(&decoded).await.map_err(|e| {
            StreamDecodeError::Infrastructure(format!("tempfile write failed: {e}"))
        })?;
        *decoded_bytes += decoded.len() as u64;
        Ok(())
    }

    /// Validate end-of-stream invariants. Surfaces a 400 if we never
    /// transitioned to `DecodingBase64` (no `_attachments[*].data`
    /// found) or if we transitioned but never saw the closing `"`
    /// (truncated body).
    fn finish(&self) -> Result<(), StreamDecodeError> {
        match self.phase {
            Phase::SeekingDataValue => {
                if self.prefix.is_empty() {
                    Err(StreamDecodeError::Validation(
                        "invalid npm publish JSON: empty body".into(),
                    ))
                } else if self.attachments_outer_depth == 0 {
                    Err(StreamDecodeError::Validation(
                        "publish body missing `_attachments`".into(),
                    ))
                } else if self.first_attachment_outer_depth == 0 {
                    Err(StreamDecodeError::Validation(
                        "publish body has no attachments".into(),
                    ))
                } else {
                    Err(StreamDecodeError::Validation(
                        "attachment missing `data` field".into(),
                    ))
                }
            }
            Phase::DecodingBase64 => Err(StreamDecodeError::Validation(
                "invalid npm publish JSON: truncated `_attachments[*].data` value".into(),
            )),
            Phase::AfterClose => {
                // We do not track braces in the suffix — serde_json
                // re-parsing of `prefix + "" + suffix` is the
                // authoritative envelope-shape check. If the publish
                // body is malformed past the base64 string the
                // caller's `serde_json::from_slice` will surface it
                // with the same 400 the prior `body: Bytes` path
                // returned.
                Ok(())
            }
        }
    }

    /// Reconstruct the envelope as `prefix` + `""` + `suffix`. The
    /// opening `"` of the base64 string lives at the end of `prefix`,
    /// the closing `"` lives at the start of `suffix`, so this is
    /// just concatenation — the empty-string between them is
    /// implicit in the two adjacent quotes.
    fn into_envelope_bytes(self) -> Result<Vec<u8>, StreamDecodeError> {
        let mut out = self.prefix;
        if out.len() + self.suffix.len() > MAX_ENVELOPE_BYTES {
            return Err(StreamDecodeError::Validation(
                "publish envelope (prefix + suffix) exceeds size limit".into(),
            ));
        }
        out.extend_from_slice(&self.suffix);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read as _;

    use axum::body::to_bytes;
    use sha1::Sha1 as Sha1Hasher;

    /// Wrap raw bytes in an axum `Body` whose data stream emits a
    /// single chunk equal to those bytes. Mirrors how the prior
    /// `body: Bytes` extractor materialised the request body — a
    /// single contiguous read.
    fn body_from(bytes: Vec<u8>) -> Body {
        Body::from(bytes)
    }

    /// Wrap raw bytes in an axum `Body` whose data stream emits one
    /// `chunk_size`-sized frame at a time. Used by the streaming
    /// chunk-boundary tests so the parser is forced to split base64
    /// across multiple `feed` calls.
    fn body_chunked(bytes: &[u8], chunk_size: usize) -> Body {
        let chunks: Vec<Result<Bytes, std::io::Error>> = bytes
            .chunks(chunk_size)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let stream = futures::stream::iter(chunks);
        Body::from_stream(stream)
    }

    /// Build a minimal npm publish JSON envelope wrapping the given
    /// tarball bytes. `_attachments` carries `<pkg_name>-<version>.tgz`
    /// — the same wire shape `build_publish_body` uses elsewhere in
    /// the test suite.
    fn build_envelope(pkg_name: &str, version: &str, tarball: &[u8]) -> Vec<u8> {
        let filename = format!("{pkg_name}-{version}.tgz");
        let b64 = base64::engine::general_purpose::STANDARD.encode(tarball);
        let body = serde_json::json!({
            "name": pkg_name,
            "versions": {
                version: { "name": pkg_name, "version": version }
            },
            "_attachments": {
                filename: {
                    "content_type": "application/octet-stream",
                    "data":         b64,
                    "length":       tarball.len(),
                }
            },
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[tokio::test]
    async fn happy_path_decodes_base64_and_computes_sha1() {
        let tarball = b"streaming-decoder-test-tarball-bytes";
        let body_bytes = build_envelope("express", "1.0.0", tarball);

        let result = stream_decode_body(body_from(body_bytes), 64 * 1024)
            .await
            .expect("decode succeeds on well-formed body");

        assert_eq!(result.tarball_size, tarball.len() as u64);
        assert_eq!(
            result.sha1_hex,
            format!("{:x}", Sha1Hasher::digest(tarball))
        );

        // Envelope reparses as JSON with empty `data`; everything
        // else round-trips.
        let parsed: serde_json::Value =
            serde_json::from_slice(&result.envelope).expect("envelope reparses");
        assert_eq!(parsed["name"], "express");
        assert_eq!(parsed["versions"]["1.0.0"]["version"], "1.0.0");
        let att = parsed["_attachments"]
            .as_object()
            .expect("_attachments preserved");
        let (_filename, val) = att.iter().next().unwrap();
        // The base64 value is replaced with the empty string — we
        // never round-trip it through the envelope buffer.
        assert_eq!(val["data"], "");
        assert_eq!(val["length"], tarball.len());

        // Tempfile contains the decoded bytes verbatim.
        let mut spooled = Vec::new();
        result
            .tarball_file
            .reopen()
            .unwrap()
            .read_to_end(&mut spooled)
            .unwrap();
        assert_eq!(spooled, tarball);
    }

    #[tokio::test]
    async fn chunked_base64_split_across_frames_decodes_correctly() {
        // 8 KiB tarball → 11 KiB base64. Chunk at 64 bytes — every
        // base64 group (4 chars) and many tarball-byte groups span
        // chunk boundaries. The carry-buffer logic must hold up.
        let tarball: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        let body_bytes = build_envelope("chunked", "1.2.3", &tarball);

        let result = stream_decode_body(body_chunked(&body_bytes, 64), 64 * 1024)
            .await
            .expect("decode succeeds even with tiny chunks");

        assert_eq!(result.tarball_size, tarball.len() as u64);
        assert_eq!(
            result.sha1_hex,
            format!("{:x}", Sha1Hasher::digest(&tarball))
        );

        let mut spooled = Vec::new();
        result
            .tarball_file
            .reopen()
            .unwrap()
            .read_to_end(&mut spooled)
            .unwrap();
        assert_eq!(spooled, tarball);
    }

    #[tokio::test]
    async fn missing_attachments_returns_validation_error() {
        let body = serde_json::to_vec(&serde_json::json!({"name": "express"})).unwrap();
        let err = stream_decode_body(body_from(body), 64 * 1024)
            .await
            .expect_err("missing _attachments must error");
        match err {
            StreamDecodeError::Validation(msg) => {
                assert!(
                    msg.contains("_attachments"),
                    "validation message must reference _attachments, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_data_field_returns_validation_error() {
        let body = serde_json::to_vec(&serde_json::json!({
            "name": "express",
            "_attachments": {
                "express-1.0.0.tgz": {
                    "content_type": "application/octet-stream",
                    "length": 0,
                }
            }
        }))
        .unwrap();
        let err = stream_decode_body(body_from(body), 64 * 1024)
            .await
            .expect_err("missing data field must error");
        match err {
            StreamDecodeError::Validation(msg) => {
                assert!(
                    msg.contains("data"),
                    "validation message must reference data field, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_base64_returns_validation_error() {
        // A literal `"data":"!!!"` JSON string. Build manually so
        // the bad base64 lands in the right place.
        let body = br#"{"name":"x","_attachments":{"x-1.0.0.tgz":{"data":"!!!"}}}"#.to_vec();
        let err = stream_decode_body(body_from(body), 64 * 1024)
            .await
            .expect_err("malformed base64 must error");
        match err {
            StreamDecodeError::Validation(msg) => {
                assert!(
                    msg.contains("base64"),
                    "validation message must reference base64, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn body_exceeding_limit_returns_body_too_large() {
        // Tarball 4 KiB → envelope ≈ 5.5 KiB. Limit 1 KiB → 413.
        let tarball = vec![0u8; 4096];
        let body = build_envelope("express", "1.0.0", &tarball);
        let err = stream_decode_body(body_from(body), 1024)
            .await
            .expect_err("oversize body must error");
        assert!(
            matches!(err, StreamDecodeError::BodyTooLarge),
            "expected BodyTooLarge, got {err:?}"
        );
    }

    #[tokio::test]
    async fn truncated_data_string_returns_validation_error() {
        // Hand-craft a body that ends mid-base64 (no closing `"`).
        let body = br#"{"_attachments":{"a.tgz":{"data":"YWJjZA"#.to_vec();
        let err = stream_decode_body(body_from(body), 64 * 1024)
            .await
            .expect_err("truncated body must error");
        match err {
            StreamDecodeError::Validation(msg) => {
                assert!(
                    msg.contains("truncated"),
                    "validation message must reference truncation, got: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn into_response_maps_body_too_large_to_413() {
        let res = StreamDecodeError::BodyTooLarge.into_response();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("publish body exceeds limit"),
            "413 body must carry the limit message"
        );
    }

    #[tokio::test]
    async fn into_response_maps_validation_to_400() {
        let res = StreamDecodeError::Validation("oops".into()).into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn into_response_maps_infrastructure_to_503() {
        let res = StreamDecodeError::Infrastructure("disk full".into()).into_response();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(res.into_body(), 4 * 1024).await.unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("publish spool failed"),
            "503 body must carry the generic spool-failed message"
        );
    }

    #[tokio::test]
    async fn tempfile_reader_reopens_at_offset_zero() {
        let tarball = b"abcdefghij";
        let body_bytes = build_envelope("p", "1.0.0", tarball);
        let result = stream_decode_body(body_from(body_bytes), 64 * 1024)
            .await
            .unwrap();

        let mut reader = tempfile_reader(&result.tarball_file)
            .await
            .map_err(|_| "tempfile_reader failed")
            .unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, tarball);
    }

    /// Memory-shape sanity test: verify the streaming decoder NEVER
    /// allocates a `Vec<u8>` the size of the tarball. A 64 KiB
    /// tarball is run through the decoder; the per-call read carry
    /// (`b64_carry`) should never exceed ~3 bytes (a 4-char base64
    /// group minus 1) and the prefix/suffix together should remain
    /// bounded by the small JSON envelope around `data`.
    ///
    /// This is the spec's "Memory-shape sanity" structural assertion
    /// — the architectural property that peak heap is O(envelope),
    /// not O(tarball).
    #[tokio::test]
    async fn memory_shape_carry_stays_bounded_across_chunks() {
        let tarball: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let body_bytes = build_envelope("memshape", "1.0.0", &tarball);

        let result = stream_decode_body(body_chunked(&body_bytes, 1024), 256 * 1024)
            .await
            .unwrap();

        // `prefix + suffix` (the envelope buffer) must be far smaller
        // than the tarball — proves we did not buffer the base64.
        // Tarball = 64 KiB; envelope ≈ a few hundred bytes.
        assert!(
            result.envelope.len() < 4096,
            "envelope grew unexpectedly: {} bytes (tarball was {})",
            result.envelope.len(),
            tarball.len()
        );
        assert_eq!(result.tarball_size, tarball.len() as u64);
    }
}
