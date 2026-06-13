//! Generic pull-through projection-cache envelope (ADR 0026).
//!
//! The npm / cargo / pypi proxy caches each stored their small upstream
//! **projection** in the `EphemeralStore` behind a per-format `Cached*Projection`
//! struct (`CachedNpmProjection`, `CachedCargoProjection`, `CachedPypiProjection`).
//! All three carried `{ projection, fetched_at }` and serialised to the EXACT
//! same compact binary frame:
//!
//! ```text
//! [ version u8 = 1 ][ fetched_at_millis i64 BE ][ serde_json(projection) ]
//! ```
//!
//! with byte-identical `encode` / `decode` / `is_fresh` / `from_projection`
//! bodies. That ~50-lines-times-three duplication was the main jscpd
//! duplication-gate risk before more format code lands. This module collapses
//! the three into one generic [`CachedProjection<P>`] parameterised over the
//! projection type `P` (serde bounds only — the concrete projection types stay
//! supplied at the format-crate use sites, so `hort-http-core` does **not** gain
//! a `hort-formats` dependency).
//!
//! # Binary-frame invariant
//!
//! The frame is BYTE-IDENTICAL to the retired per-format envelopes: the version
//! byte ([`CACHE_FORMAT_VERSION`] = 1), the 8-byte big-endian millisecond
//! timestamp, and the `serde_json` body are unchanged. This preserves the
//! rolling-deploy cold-cache contract — a pre-amendment base64-JSON envelope
//! (first byte `b'{'` ≠ 1) or a raw-body frame whose payload is not a valid
//! `serde_json(P)` decodes to `None`, i.e. a cache miss that re-fetches.
//!
//! # Per-format TTLs
//!
//! The fresh / stale TTL constants stay where they are in each format crate
//! (`NPM_PACKUMENT_FRESH_TTL`, `CARGO_INDEX_FRESH_TTL`, `PYPI_SIMPLE_FRESH_TTL`,
//! …); the freshness check takes the format's `fresh_ttl` as a parameter rather
//! than hard-coding one.

use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Cache-frame format version. A decode rejects any other first byte (e.g. a
/// pre-amendment base64-JSON envelope's `b'{'`), resolving a rolling-deploy
/// cold-cache event to "miss + re-fetch".
pub const CACHE_FORMAT_VERSION: u8 = 1;

/// Fixed header length: 1-byte version + 8-byte big-endian `i64` millis.
pub const CACHE_HEADER_LEN: usize = 1 + 8;

/// A cached upstream **projection** with its fetch timestamp, serialised to the
/// compact binary frame `[version u8 = 1][fetched_at_ms i64 BE][serde_json(P)]`.
///
/// Generic over the projection type `P` — the npm packument projection, the
/// cargo `Vec<CargoVersionLine>`, the pypi simple-index projection, etc. — with
/// `serde` bounds only, so the concrete projection types stay in the format
/// crates and `hort-http-core` carries no format dependency.
#[derive(Debug, Clone)]
pub struct CachedProjection<P> {
    pub projection: P,
    pub fetched_at: DateTime<Utc>,
}

impl<P> CachedProjection<P>
where
    P: Serialize + DeserializeOwned,
{
    /// Stamp a projection with `fetched_at = Utc::now()`.
    pub fn from_projection(projection: P) -> Self {
        Self {
            projection,
            fetched_at: Utc::now(),
        }
    }

    /// Serialise to the compact binary frame
    /// `[CACHE_FORMAT_VERSION][fetched_at_ms i64 BE][serde_json(projection)]`.
    ///
    /// `serde_json` cannot fail for an in-memory projection (plain strings +
    /// RFC3339 timestamps / `serde_json::Value` fields the projector itself
    /// deserialised). Falls back to an empty body on the impossible error so a
    /// cache-write never panics; the consumer treats a malformed/empty frame as
    /// a miss.
    pub fn encode(&self) -> Bytes {
        let json = serde_json::to_vec(&self.projection).unwrap_or_default();
        let mut buf = Vec::with_capacity(CACHE_HEADER_LEN + json.len());
        buf.push(CACHE_FORMAT_VERSION);
        buf.extend_from_slice(&self.fetched_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&json);
        Bytes::from(buf)
    }

    /// Decode a frame. Returns `None` on:
    /// - empty / too-short input (`< CACHE_HEADER_LEN`),
    /// - unrecognised format version (e.g. a pre-amendment base64-JSON envelope
    ///   whose first byte `b'{'` ≠ 1, or a pre-amendment raw-body frame whose
    ///   payload is not a valid `serde_json(P)` — either way a rolling-deploy
    ///   cold-cache event resolves to "miss + re-fetch"),
    /// - a non-representable timestamp,
    /// - a payload that is not a valid `serde_json(P)`.
    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < CACHE_HEADER_LEN || raw[0] != CACHE_FORMAT_VERSION {
            return None;
        }
        let ts_bytes: [u8; 8] = raw[1..CACHE_HEADER_LEN].try_into().ok()?;
        let ts_millis = i64::from_be_bytes(ts_bytes);
        let fetched_at = DateTime::<Utc>::from_timestamp_millis(ts_millis)?;
        let projection: P = serde_json::from_slice(&raw[CACHE_HEADER_LEN..]).ok()?;
        Some(Self {
            projection,
            fetched_at,
        })
    }

    /// `true` while the entry is within `fresh_ttl` of `now` (and not stamped in
    /// the future). Past the fresh window the entry is stale-but-decodable —
    /// the `stale-while-error` fallback the format crates rely on.
    pub fn is_fresh(&self, now: DateTime<Utc>, fresh_ttl: Duration) -> bool {
        let age = now.signed_duration_since(self.fetched_at).num_seconds();
        age >= 0 && (age as u64) < fresh_ttl.as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    /// A small projection-like type standing in for the format crates'
    /// concrete projections. Serde-derive only — exactly the bound the generic
    /// requires.
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestProjection {
        latest: Option<String>,
        versions: Vec<String>,
    }

    fn sample() -> TestProjection {
        TestProjection {
            latest: Some("1.2.3".to_string()),
            versions: vec!["1.0.0".to_string(), "1.2.3".to_string()],
        }
    }

    #[test]
    fn from_projection_stamps_now() {
        let before = Utc::now().timestamp_millis();
        let entry = CachedProjection::from_projection(sample());
        let after = Utc::now().timestamp_millis();
        let ts = entry.fetched_at.timestamp_millis();
        assert!(ts >= before && ts <= after, "fetched_at must be ~now");
    }

    #[test]
    fn frame_round_trips() {
        let entry = CachedProjection::from_projection(sample());
        let encoded = entry.encode();
        let decoded = CachedProjection::<TestProjection>::decode(&encoded).expect("decode");
        assert_eq!(decoded.projection, sample());
        // fetched_at preserved to millisecond precision.
        assert_eq!(
            decoded.fetched_at.timestamp_millis(),
            entry.fetched_at.timestamp_millis()
        );
    }

    /// The frame layout is load-bearing across rolling deploys; pin the EXACT
    /// bytes against a known fixture so an accidental layout change (version
    /// byte, endianness, header order) can't drift silently.
    #[test]
    fn frame_is_byte_identical_to_known_fixture() {
        let entry = CachedProjection {
            projection: TestProjection {
                latest: None,
                versions: vec![],
            },
            fetched_at: DateTime::<Utc>::from_timestamp_millis(1_000).expect("valid ts"),
        };
        let encoded = entry.encode();
        // [version=1][i64 BE 1000 = 0x00..0x03E8][serde_json body]
        let mut expected = vec![CACHE_FORMAT_VERSION];
        expected.extend_from_slice(&1_000i64.to_be_bytes());
        expected.extend_from_slice(br#"{"latest":null,"versions":[]}"#);
        assert_eq!(
            encoded.as_ref(),
            expected.as_slice(),
            "binary frame must be byte-identical to the pinned fixture"
        );
    }

    #[test]
    fn decode_rejects_too_short_input() {
        assert!(CachedProjection::<TestProjection>::decode(&[]).is_none());
        // 8 bytes < 9-byte header.
        assert!(CachedProjection::<TestProjection>::decode(&[1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn decode_rejects_unrecognized_version_byte() {
        // Legacy base64-JSON envelope: first byte `{` (0x7B) ≠ version 1.
        let legacy = br#"{"body":"abc","fetched_at":"2024-01-01T00:00:00Z"}"#;
        assert!(CachedProjection::<TestProjection>::decode(legacy).is_none());
    }

    #[test]
    fn decode_rejects_valid_header_but_non_p_payload() {
        // Valid version byte + header, but a JSON array can't be a
        // `TestProjection` (an object) → None. This is the cold-cache
        // "old raw-body frame decodes as None → miss + re-fetch" contract.
        let mut frame = vec![CACHE_FORMAT_VERSION];
        frame.extend_from_slice(&0i64.to_be_bytes());
        frame.extend_from_slice(b"[1,2,3]");
        assert!(CachedProjection::<TestProjection>::decode(&frame).is_none());
    }

    #[test]
    fn is_fresh_window() {
        let now = Utc::now();
        let entry = CachedProjection {
            projection: sample(),
            fetched_at: now,
        };
        assert!(entry.is_fresh(now, Duration::from_secs(60)));
        // 120 s old, 60 s window → stale.
        let stale = CachedProjection {
            projection: sample(),
            fetched_at: now - chrono::Duration::seconds(120),
        };
        assert!(!stale.is_fresh(now, Duration::from_secs(60)));
        // A future-stamped entry is treated as not-fresh (negative age).
        let future = CachedProjection {
            projection: sample(),
            fetched_at: now + chrono::Duration::seconds(120),
        };
        assert!(!future.is_fresh(now, Duration::from_secs(60)));
    }
}
