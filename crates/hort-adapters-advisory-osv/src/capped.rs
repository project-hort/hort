//! Byte bounds on the three OSV responses this adapter reads.
//!
//! Every one of them was read without a byte bound: the batch query and
//! the per-record hydration each buffered a whole body into a `String`,
//! and the bulk archive copied a whole body to disk. The only bound was
//! `OsvAdvisoryConfig::request_timeout`, and a timeout bounds *duration*
//! — a hostile or compromised endpoint can stay comfortably inside 30
//! seconds while serving more bytes than the process has memory, or than
//! the host has disk.
//!
//! The shape here mirrors `hort_adapters_oidc::internal::get_capped_body`
//! — stream the body and fail on the first chunk that would cross the
//! cap, rather than read it all and check afterwards, which would mean
//! holding the thing the cap exists to refuse. Two differences, both
//! because of where this sits: the helpers take a `Response` the caller
//! has already status-checked (OSV's own `upstream_4xx` / `upstream_5xx`
//! classification happens before the body is touched), and one of them
//! writes to a sink rather than returning bytes, because a bulk archive
//! belongs on disk either way.
//!
//! **Over-cap is an error, never a truncation.** ADR 0007's direction is
//! that absent evidence must not read as clean evidence, and a truncated
//! advisory feed is the purest form of that mistake: a short JSON body
//! fails to parse (loud), but a *truncated archive* parses fine and
//! simply contains fewer advisories — a package with a known
//! vulnerability comes back clean, and the feed checkpoint advances over
//! the window that would have reported it.

use futures::StreamExt;

use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Why a capped read did not produce a body.
///
/// Two variants rather than one because the caller's classification
/// differs: a transport failure says the upstream is unreachable or
/// broken, a cap breach says it served more than this adapter will read.
/// Collapsing them would send an operator to the network for a problem
/// that is in the response.
#[derive(Debug)]
pub(crate) enum CappedReadError {
    /// The body stream failed mid-read (connection reset, TLS error,
    /// decode failure).
    Stream(String),
    /// The body crossed the cap. `bytes_read` is how far the read got
    /// before refusing — the count including the chunk that crossed, so
    /// it is a lower bound on the body's real size, not the body's size.
    TooLarge { bytes_read: u64, cap: u64 },
}

impl std::fmt::Display for CappedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(msg) => write!(f, "{msg}"),
            Self::TooLarge { bytes_read, cap } => write!(
                f,
                "response body exceeded the {cap}-byte cap (read {bytes_read} bytes before \
                 refusing); refusing to read it rather than truncating it"
            ),
        }
    }
}

/// Read `response`'s body as UTF-8 text, refusing it past `cap` bytes.
///
/// The cap is counted on the **bytes on the wire**, before UTF-8
/// validation, because that is the only count available while the
/// decision is still cheap to make.
pub(crate) async fn read_capped_text(
    response: reqwest::Response,
    cap: u64,
) -> Result<String, CappedReadError> {
    let bytes = read_capped_bytes(response, cap).await?;
    String::from_utf8(bytes)
        .map_err(|e| CappedReadError::Stream(format!("body is not valid UTF-8: {e}")))
}

/// Read `response`'s body into memory, refusing it past `cap` bytes.
async fn read_capped_bytes(
    response: reqwest::Response,
    cap: u64,
) -> Result<Vec<u8>, CappedReadError> {
    // Pre-allocate against the cap only up to a modest ceiling: a cap is
    // a refusal threshold, not a size estimate, and reserving it up front
    // would spend the worst case on every ordinary response.
    let mut buf: Vec<u8> = Vec::with_capacity(cap.min(64 * 1024) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| CappedReadError::Stream(format!("body stream read failed: {e}")))?;
        let next = buf.len() as u64 + chunk.len() as u64;
        if next > cap {
            return Err(CappedReadError::TooLarge {
                bytes_read: next,
                cap,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Copy `response`'s body into `sink`, refusing it past `cap` bytes.
///
/// For the bulk archive, which is spilled to a tempfile rather than
/// buffered. The cap is on the **compressed** body: the archive's own
/// decompression bounds live in `hort_formats::archive_bounds` and
/// cannot engage until the whole compressed body is already on disk,
/// which is precisely the gap this closes.
///
/// A refusal leaves whatever was already written in `sink`. The caller
/// must treat the whole fetch as failed rather than parse what landed —
/// a partial ZIP is not a smaller feed, it is an unknown one.
pub(crate) async fn copy_capped<W>(
    response: reqwest::Response,
    sink: &mut W,
    cap: u64,
) -> Result<u64, CappedReadError>
where
    W: AsyncWrite + Unpin,
{
    let mut written: u64 = 0;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| CappedReadError::Stream(format!("body stream read failed: {e}")))?;
        let next = written + chunk.len() as u64;
        if next > cap {
            return Err(CappedReadError::TooLarge {
                bytes_read: next,
                cap,
            });
        }
        sink.write_all(&chunk)
            .await
            .map_err(|e| CappedReadError::Stream(format!("body write failed: {e}")))?;
        written = next;
    }
    sink.flush()
        .await
        .map_err(|e| CappedReadError::Stream(format!("body flush failed: {e}")))?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn serve(body: Vec<u8>) -> (MockServer, reqwest::Response) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        let response = reqwest::Client::builder()
            .build()
            .expect("client")
            .get(server.uri())
            .send()
            .await
            .expect("send");
        (server, response)
    }

    #[tokio::test]
    async fn text_at_the_cap_is_accepted() {
        let body = vec![b'a'; 100];
        let (_s, response) = serve(body.clone()).await;
        let out = read_capped_text(response, 100).await.expect("at cap");
        assert_eq!(out.len(), 100);
    }

    #[tokio::test]
    async fn text_one_byte_over_the_cap_is_refused() {
        let (_s, response) = serve(vec![b'a'; 101]).await;
        let err = read_capped_text(response, 100).await.expect_err("over cap");
        match err {
            CappedReadError::TooLarge { bytes_read, cap } => {
                assert_eq!(cap, 100);
                assert!(bytes_read > cap, "bytes_read must exceed the cap it broke");
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// An over-cap body must be distinguishable from a *short* one, and
    /// the short one must not be mistaken for a refusal: a body below
    /// the cap that is simply not the document expected is the caller's
    /// parse problem, not the cap's.
    #[tokio::test]
    async fn a_short_body_is_not_reported_as_over_cap() {
        let (_s, response) = serve(b"{}".to_vec()).await;
        let out = read_capped_text(response, 1024).await.expect("short body");
        assert_eq!(out, "{}");
    }

    #[tokio::test]
    async fn non_utf8_text_is_a_stream_error_not_a_cap_breach() {
        let (_s, response) = serve(vec![0xff, 0xfe, 0xfd]).await;
        let err = read_capped_text(response, 1024)
            .await
            .expect_err("invalid UTF-8");
        match err {
            CappedReadError::Stream(msg) => assert!(msg.contains("not valid UTF-8"), "{msg}"),
            other => panic!("expected Stream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn copy_at_the_cap_is_accepted_and_reports_the_byte_count() {
        let (_s, response) = serve(vec![7u8; 4096]).await;
        let mut sink: Vec<u8> = Vec::new();
        let n = copy_capped(response, &mut sink, 4096)
            .await
            .expect("at cap");
        assert_eq!(n, 4096);
        assert_eq!(sink.len(), 4096);
    }

    #[tokio::test]
    async fn copy_over_the_cap_is_refused() {
        let (_s, response) = serve(vec![7u8; 5000]).await;
        let mut sink: Vec<u8> = Vec::new();
        let err = copy_capped(response, &mut sink, 4096)
            .await
            .expect_err("over cap");
        match err {
            CappedReadError::TooLarge { bytes_read, cap } => {
                assert_eq!(cap, 4096);
                assert!(bytes_read > cap);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// The error text an operator reads has to say which of the two
    /// things happened, because the remedies differ: raise the cap (or
    /// look at the endpoint) versus look at the network.
    #[test]
    fn display_distinguishes_a_cap_breach_from_a_transport_failure() {
        let too_large = CappedReadError::TooLarge {
            bytes_read: 11,
            cap: 10,
        }
        .to_string();
        assert!(
            too_large.contains("exceeded the 10-byte cap"),
            "{too_large}"
        );
        assert!(
            too_large.contains("rather than truncating"),
            "the message must say the body was refused, not shortened: {too_large}"
        );

        let stream = CappedReadError::Stream("connection reset".into()).to_string();
        assert_eq!(stream, "connection reset");
        assert!(!stream.contains("cap"), "a transport failure names no cap");
    }
}
