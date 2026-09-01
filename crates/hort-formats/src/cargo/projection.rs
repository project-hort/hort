//! Cargo sparse-index NDJSON streaming projector (see ADR 0026).
//!
//! The sparse-index format is line-delimited JSON — one root JSON
//! object per line. `serde_json::Deserializer::from_reader(reader)`'s
//! built-in `.into_iter::<T>()` already produces a streaming iterator
//! of root-level values, so the projector is a thin wrapper that
//! collects them into the consumer's `Vec<CargoVersionLine>` shape.
//!
//! No custom `Visitor` and no per-version cap — each line is a single
//! root-object that the deserializer reads to its closing brace; the
//! sparse-index format bounds the per-line size structurally (Cargo's
//! upstream registry does not emit multi-MB lines). The `CountingReader`
//! cap surface kept uniform across the four formats elsewhere is
//! deliberately absent here because Cargo's shape doesn't need it.
//!
//! **Fail-closed malformed-line policy (reject-on-invalid, NOT
//! skip-and-continue).** A malformed NDJSON line anywhere in the body
//! rejects the *whole* projection with `DomainError::Validation`; the
//! projector never returns a truncated partial. The consumer
//! (`fetch_and_project`) is validate-before-commit, so a rejected body
//! is never cached or mirrored — the prior cache state stands.
//!
//! No new workspace dep — `serde_json::Deserializer::into_iter` is
//! stock serde_json.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::upstream_proxy::MetadataProjector;

/// One per-version entry parsed out of a Cargo sparse-index NDJSON
/// stream. Field set matches the consumer (`ProxyCargoSource::fetch`)
/// — every per-version field the unified handler needs.
///
/// Derives `Serialize` (in addition to `Deserialize`) so the cargo proxy
/// can cache the **projection** (`Vec<CargoVersionLine>`) in Redis under
/// `cargo_index_proj:` instead of the raw NDJSON body. The raw body lives
/// in the `MetadataMirrorStore`; the projection round-trips through serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CargoVersionLine {
    #[serde(default)]
    pub name: String,
    pub vers: String,
    #[serde(default)]
    pub cksum: String,
    #[serde(default)]
    pub deps: serde_json::Value,
    #[serde(default)]
    pub features: serde_json::Value,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default)]
    pub rust_version: Option<String>,
    #[serde(default)]
    pub v: Option<u32>,
    #[serde(default)]
    pub features2: Option<serde_json::Value>,
    /// Publish timestamp, straight from whatever the upstream NDJSON
    /// line supplies under this key, in cargo's strict `serde_pubtime`
    /// wire format (`yyyy-mm-ddThh:mm:ssZ`) rather than general RFC
    /// 3339. crates.io now serves this field in exactly that shape, but
    /// it is deliberately unread here: the served index's `pubtime`
    /// value is computed independently, downstream of the projection,
    /// from hort's own artifact record (see `ProxyCargoSource::fetch`)
    /// — this field is never read for that computation. It exists so a
    /// future upstream-passthrough amendment can round-trip the
    /// upstream value without a schema change.
    ///
    /// `#[serde(default)]` like every other optional field above: a
    /// projection cached before this field existed decodes as `None`,
    /// no forced cache invalidation needed.
    #[serde(default)]
    pub pubtime: Option<DateTime<Utc>>,
}

/// Streaming projector.
#[derive(Debug, Default, Clone, Copy)]
pub struct CargoSparseIndexProjector;

impl CargoSparseIndexProjector {
    pub fn new() -> Self {
        Self
    }
}

impl MetadataProjector for CargoSparseIndexProjector {
    type Projection = Vec<CargoVersionLine>;
    fn project<R: std::io::Read>(self, reader: R) -> DomainResult<Vec<CargoVersionLine>> {
        let mut out = Vec::new();
        // `into_iter::<T>()` consumes root-level JSON values from the
        // reader one at a time — exactly what NDJSON wants. A trailing
        // EOF (no more values) ends the walk; any other parse error is
        // a malformed line and is REJECTED fail-closed (see below).
        let de = serde_json::Deserializer::from_reader(reader);
        for value in de.into_iter::<CargoVersionLine>() {
            match value {
                Ok(line) => out.push(line),
                Err(e) if e.is_eof() => break,
                Err(e) => {
                    // Fail-closed: reject-on-invalid, NOT skip-and-continue.
                    // A malformed line anywhere fails the whole
                    // projection — no truncated partial is returned.
                    // Because the consumer is validate-before-commit,
                    // nothing is cached or mirrored, so the prior cache
                    // state stands. Legitimate Cargo upstreams emit
                    // well-formed NDJSON; this only bites on upstream
                    // corruption, which the operator chose to reject
                    // rather than serve partially.
                    return Err(DomainError::Validation(format!(
                        "cargo sparse-index: malformed NDJSON line: {e}"
                    )));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn project(body: &[u8]) -> DomainResult<Vec<CargoVersionLine>> {
        CargoSparseIndexProjector::new().project(Cursor::new(body))
    }

    #[test]
    fn empty_input_yields_empty_projection() {
        let p = project(b"").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn ndjson_round_trip_three_versions() {
        let body =
            br#"{"name":"foo","vers":"1.0.0","cksum":"a","deps":[],"features":{},"yanked":false}
{"name":"foo","vers":"1.0.1","cksum":"b","deps":[],"features":{},"yanked":false}
{"name":"foo","vers":"2.0.0","cksum":"c","deps":[],"features":{},"yanked":true}
"#;
        let p = project(body).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].vers, "1.0.0");
        assert_eq!(p[0].cksum, "a");
        assert!(!p[0].yanked);
        assert_eq!(p[2].vers, "2.0.0");
        assert!(p[2].yanked);
    }

    #[test]
    fn cksum_round_trips_verbatim() {
        // `cksum` is Cargo's upstream-checksum field (see ADR 0006).
        let body = b"{\"name\":\"foo\",\"vers\":\"1.0.0\",\"cksum\":\"abc123\"}\n";
        let p = project(body).unwrap();
        assert_eq!(p[0].cksum, "abc123");
    }

    #[test]
    fn malformed_line_is_fatal() {
        use hort_domain::error::DomainError;
        let body = br#"{"name":"foo","vers":"1.0.0"}
not json at all
{"name":"foo","vers":"1.0.1"}
"#;
        // Fail-closed: reject-on-invalid. A malformed line rejects the
        // whole projection — the projector returns Validation rather
        // than the OLD silent `Ok`-with-truncated-partial. Because the
        // consumer is validate-before-commit, nothing is cached or
        // mirrored on this path.
        let err = project(body).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn malformed_line_in_middle_is_rejected_not_truncated() {
        use hort_domain::error::DomainError;
        // line1 ok, line2 malformed, line3 ok — fail-closed rejects the
        // whole projection rather than returning a truncated partial.
        let body = b"{\"name\":\"a\",\"vers\":\"1.0.0\",\"cksum\":\"x\",\"yanked\":false}\n{ not json \n{\"name\":\"a\",\"vers\":\"2.0.0\",\"cksum\":\"y\",\"yanked\":false}\n";
        let err = project(&body[..]).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }

    #[test]
    fn pubtime_absent_on_line_defaults_to_none() {
        // A line without the key must still parse — pre-`pubtime`
        // upstream snapshots and any upstream that omits it stay valid.
        let body = br#"{"name":"foo","vers":"1.0.0","cksum":"a"}"#;
        let p = project(body).unwrap();
        assert!(p[0].pubtime.is_none());
    }

    #[test]
    fn pubtime_present_on_line_round_trips() {
        // Forward-compat: a future upstream (or a chained hort mirror)
        // that does serve `pubtime` round-trips it verbatim through the
        // projector, even though the served proxy index's own `pubtime`
        // is computed independently downstream (see
        // `ProxyCargoSource::fetch`).
        let body = br#"{"name":"foo","vers":"1.0.0","cksum":"a","pubtime":"2024-01-02T03:04:05Z"}"#;
        let p = project(body).unwrap();
        assert_eq!(
            p[0].pubtime.map(|t| t.to_rfc3339()),
            Some("2024-01-02T03:04:05+00:00".to_string())
        );
    }

    #[test]
    fn old_cached_projection_json_without_pubtime_key_still_deserializes() {
        // Simulates decoding a `CachedCargoProjection` entry written by a
        // pre-amendment binary: the serialized `CargoVersionLine` array
        // has no `pubtime` key at all. `#[serde(default)]` must make this
        // a non-event — no forced cache invalidation, no decode failure.
        let old_cache_json = r#"[{"name":"foo","vers":"1.0.0","cksum":"a","deps":[],
            "features":{},"yanked":false,"links":null,"rust_version":null}]"#;
        let lines: Vec<CargoVersionLine> = serde_json::from_str(old_cache_json)
            .expect("pre-amendment cached projection JSON must still decode");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].pubtime.is_none(),
            "a pre-amendment cache entry has no pubtime data to offer"
        );
    }

    #[test]
    fn unknown_fields_on_line_are_skipped_without_failing() {
        let body = br#"{"name":"foo","vers":"1.0.0","cksum":"a","_internal":42,"_meta":{"x":1}}"#;
        let p = project(body).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].vers, "1.0.0");
    }

    #[test]
    fn large_multiline_index_streams_every_line() {
        // The streaming `into_iter` walks many root-level NDJSON objects
        // without materialising the whole body as a single value tree.
        let mut body = String::new();
        for i in 0..2000 {
            body.push_str(&format!(
                "{{\"name\":\"foo\",\"vers\":\"1.0.{i}\",\"cksum\":\"c{i}\",\
                 \"deps\":[],\"features\":{{}},\"yanked\":false}}\n"
            ));
        }
        let p = project(body.as_bytes()).unwrap();
        assert_eq!(p.len(), 2000);
        assert_eq!(p[0].vers, "1.0.0");
        assert_eq!(p[1999].vers, "1.0.1999");
        assert_eq!(p[1999].cksum, "c1999");
    }
}
