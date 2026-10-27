//! Is the payload's JSONB round trip stable? Measured against a real
//! PostgreSQL, per payload shape.
//!
//! The tamper-evident chain's `event_hash` is computed at append from a
//! `serde_json::Value` the writer holds **before** the row exists, and
//! recomputed at verify from what came back out of the `event_data`
//! **JSONB** column. Postgres normalises JSON on the way in — key order,
//! whitespace, escaping, and numbers, which it stores as `numeric`. Key
//! order and whitespace are neutralised by construction (the column is
//! parsed back into a `Value`, and the chain canonicalises object keys);
//! escaping likewise, because the parse discards the dialect Postgres
//! chose to print in. What is left — whether a **number** survives
//! `serde_json` → `jsonb`/`numeric` → `serde_json` unchanged — is an open
//! question that only a real database can answer.
//!
//! Each shape is appended through the production `EventStore::append`,
//! then read back through the production verifier's own read path
//! (`PgEventChainReader` + `ChainRow::as_stream_row` +
//! `verify_stream_chain` — what `hort-server verify-event-chain` runs),
//! and two things are recorded:
//!
//! 1. **Round-trip stability** — does the stored payload canonicalise to
//!    the same bytes as the payload the writer produced?
//! 2. **Today's verdict** — does the chain verifier report `Ok` for this
//!    freshly-appended, *untampered* row?
//!
//! The two answers are independent statements and both are asserted, per
//! shape, against [`UNSTABLE_SHAPES`] by exact equality in both
//! directions: a newly-unstable shape fails, and a repaired one keeps
//! failing until the inventory is shrunk deliberately.
//!
//! `ArtifactIngested.metadata` carries every number shape here because
//! it is a genuine `serde_json::Value` event field — on the npm publish
//! path it is the client's per-version packument block, placed in the
//! event verbatim when it is under the handler's 256 KB inline
//! threshold. So the numbers below are not invented: they are the
//! numbers a publisher can put in a `package.json`. Two entry paths are
//! modelled separately because they are not equivalent:
//! `inbound-*` parses the number out of JSON text the way the HTTP layer
//! parses a request body, and `rustlit-*` has Rust code place an `f64`
//! into the field directly. No `DomainEvent` field is typed `f64` today,
//! so only the `inbound-*` path has a production producer — but the
//! field's type admits both.
//!
//! Every shape's verdict here is invariant across build configurations.
//! That was not always true: `serde_json`'s float parser is correctly
//! rounded only with the `float_roundtrip` feature, which used to arrive
//! transitively into one binary's graph and not the other's, so a
//! float-shaped entry's verdict moved between
//! `cargo test -p hort-adapters-postgres` and `cargo test --workspace`
//! — the test measured cargo's feature unification rather than the
//! payload round trip. The feature is now declared on the workspace
//! `serde_json` dependency and guarded behaviourally by
//! `hort-domain/tests/float_roundtrip_is_pinned.rs`, so the shape that
//! had to be withheld (`rustlit-17digit`) is back in the corpus below
//! and measures stable.

use std::env;

use serial_test::serial;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use hort_adapters_postgres::event_chain_reader::PgEventChainReader;
use hort_adapters_postgres::event_store::PgEventStore;
use hort_domain::events::{
    verify_stream_chain, Actor, ApiActor, ArtifactIngested, ChainRow, DomainEvent, IngestSource,
    StreamId, StreamRows, StreamVerdict,
};
use hort_domain::ports::event_chain_reader::EventChainReaderPort;
use hort_domain::ports::event_store::{AppendEvents, EventStore, EventToAppend, ExpectedVersion};
use hort_domain::types::ContentHash;

// ---------------------------------------------------------------------------
// The recorded instabilities
// ---------------------------------------------------------------------------

/// Every payload shape whose stored JSONB does **not** canonicalise back
/// to the bytes the writer produced, with the measured delta and the
/// mechanism behind it.
///
/// **Empty, and the empty state is the assertion.** An inventory of a
/// known gap, not an exemption list: the test asserts the measured
/// unstable set **equals** this constant in both directions, so a shape
/// that stops surviving the round trip fails rather than being absorbed.
///
/// It held two entries, both the same number: `-0.0` from each of the two
/// entry paths. `jsonb` stores numbers as `numeric`, which has no signed
/// zero, so a payload carrying `-0.0` was stored as `0.0` while the
/// writer had hashed `-0.0` — and `verify-event-chain` reported
/// `HashMismatch` on an untouched row. It was client-reachable:
/// `ArtifactIngested.metadata` carries an npm publisher's per-version
/// packument block verbatim when it is under the handler's inline
/// threshold.
///
/// Closed by normalising negative zero to positive zero inside
/// `hort_domain::events::stored_payload_envelope`, the single producer of
/// the stored envelope — so the value that is hashed and the value that
/// is written are the same, and both are what `numeric` can hold. The
/// two `-0.0` shapes stay in the corpus below and now measure stable;
/// that is what makes the fix visible here rather than merely absent.
const UNSTABLE_SHAPES: &[Unstable] = &[];

/// One recorded instability. See [`UNSTABLE_SHAPES`].
struct Unstable {
    /// The shape label in [`shapes`].
    shape: &'static str,
    /// Measured `path: writer -> stored` delta, asserted per shape.
    delta: &'static str,
    /// Why the bytes move. Prose — documented, not asserted.
    mechanism: &'static str,
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Fresh isolated database per run (the crate's `maybe_pool` idiom). The
/// `DATABASE_URL` read is the one `?`-shaped skip; a URL that is set but
/// unreachable panics inside `isolated_db_from` rather than reporting
/// "no database configured".
async fn maybe_pool() -> Option<PgPool> {
    let url = env::var("DATABASE_URL").ok()?;
    let pool = hort_adapters_postgres::test_support::isolated_db_from(&url).await?;
    hort_adapters_postgres::test_support::migrate_or_panic(&pool).await;
    Some(pool)
}

/// The payload shapes under test: `(label, metadata)`. The metadata
/// value becomes `ArtifactIngested.metadata` verbatim.
fn shapes() -> Vec<(&'static str, serde_json::Value)> {
    // A number as it enters on the npm publish path: parsed out of JSON
    // text by `serde_json`, exactly as the HTTP layer parses a request
    // body, then carried into the event unchanged.
    let inbound = |text: &str| -> serde_json::Value {
        serde_json::from_str(&format!("{{\"n\":{text}}}")).expect("client body must parse")
    };
    let mut out: Vec<(&'static str, serde_json::Value)> = vec![
        // Non-ASCII text, including astral-plane.
        (
            "non-ascii",
            serde_json::json!({"desc": "naïve café — 日本語 🦀", "k-é": "ß"}),
        ),
        // Every class of character `serde_json` escapes: the two
        // mandatory escapes, the five short control escapes, a `\u00XX`
        // control, DEL, and a non-ASCII separator Postgres may print
        // differently than serde does.
        (
            "serde-escapes",
            serde_json::json!({
                "s": "quote\"back\\slash\nnl\rcr\ttab\u{8}bs\u{c}ff\u{1}soh\u{7f}del\u{2028}ls"
            }),
        ),
        // Integers at and around the i64/u64 limits, and past the f64
        // exact-integer boundary.
        (
            "big-ints",
            serde_json::json!({
                "u64_max": u64::MAX, "u64_max_m1": u64::MAX - 1,
                "i64_min": i64::MIN, "i64_max": i64::MAX,
                "pow2_53_plus_1": 9007199254740993_i64, "zero": 0, "neg_one": -1
            }),
        ),
        (
            "empty-containers",
            serde_json::json!({"obj": {}, "arr": [], "nested": {"o": {}, "a": [[], {}]}, "null": null}),
        ),
        ("deep-nest", {
            let mut v = serde_json::json!({"leaf": 1, "f": 0.5});
            for i in 0..24 {
                v = serde_json::json!({format!("k{i}"): v, "sib": [i]});
            }
            v
        }),
        (
            "unsorted-keys",
            serde_json::json!({"z": 1, "a": 2, "m": {"y": 1, "b": 2}}),
        ),
        (
            "odd-keys",
            serde_json::json!({"": 1, "with\"quote": 2, "é": 3, "a.b": 4}),
        ),
        // Floats placed into the field by Rust code: rustc's
        // correctly-rounded parse of the literal, not a serde_json parse.
        ("rustlit-neg-zero", serde_json::json!({"n": -0.0_f64})),
        ("rustlit-half", serde_json::json!({"n": 0.5_f64})),
        // rustc's correctly-rounded parse of a 17-significant-digit
        // literal. This is the shape the two `serde_json` float parsers
        // disagree about, so it measures the pinned `float_roundtrip`
        // feature end to end: without it the read-back parse lands one
        // ulp away, reprints as `123456789.1234568`, and this shape
        // reads as unstable.
        (
            "rustlit-17digit",
            serde_json::json!({"n": 123456789.12345679_f64}),
        ),
    ];
    for (label, text) in [
        ("inbound--0.0", "-0.0"),
        ("inbound-0.0", "0.0"),
        ("inbound-17digit", "123456789.12345679"),
        ("inbound-third", "0.3333333333333333"),
        ("inbound-1e300", "1e300"),
        ("inbound-1e-7", "1e-7"),
        ("inbound-1.5e22", "1.5e22"),
        ("inbound-trailing-zero", "1.50"),
        ("inbound-neg-tiny", "-2.5e-10"),
        ("inbound-30-digit", "1.000000000000000000000000000001"),
        ("inbound-int-beyond-u64", "123456789012345678901234567890"),
    ] {
        out.push((label, inbound(text)));
    }
    out
}

/// Recursively re-emit every object with its keys in lexicographic
/// order. The **only** normalisation this comparison applies: key order
/// is the one difference between the writer's `Value` and the stored one
/// that is agreed immaterial (the chain sorts keys too). Whitespace and
/// escaping need no handling — parsing the column into a `Value`
/// discards whichever dialect Postgres printed in — so what survives
/// into the compared text is exactly what the round trip changed.
fn sort_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            serde_json::Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sort_keys(v)))
                    .collect(),
            )
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(sort_keys).collect())
        }
        scalar => scalar.clone(),
    }
}

/// Key-sorted serialisation — the comparison unit. Text rather than
/// `Value`, because `serde_json::Value`'s `PartialEq` compares numbers
/// with IEEE `==` and so cannot tell `-0.0` from `0.0`: the signed-zero
/// loss below is invisible to a `Value` comparison and visible to the
/// hash, which is the whole reason this test compares bytes.
fn canonical_text(value: &serde_json::Value) -> String {
    serde_json::to_string(&sort_keys(value)).expect("a Value is always serialisable")
}

/// The `path: writer -> stored` delta between two canonicalised
/// payloads, for the scalar leaves that differ. Empty when they agree.
fn scalar_delta(writer: &serde_json::Value, stored: &serde_json::Value) -> String {
    fn walk(w: &serde_json::Value, s: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        match (w, s) {
            (serde_json::Value::Object(wm), serde_json::Value::Object(sm)) => {
                let mut keys: Vec<&String> = wm.keys().chain(sm.keys()).collect();
                keys.sort();
                keys.dedup();
                for k in keys {
                    let child = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    match (wm.get(k), sm.get(k)) {
                        (Some(a), Some(b)) => walk(a, b, &child, out),
                        (Some(a), None) => out.push(format!("{child}: {a} -> <absent>")),
                        (None, Some(b)) => out.push(format!("{child}: <absent> -> {b}")),
                        (None, None) => unreachable!("key came from one of the two maps"),
                    }
                }
            }
            (serde_json::Value::Array(wa), serde_json::Value::Array(sa))
                if wa.len() == sa.len() =>
            {
                for (i, (a, b)) in wa.iter().zip(sa).enumerate() {
                    walk(a, b, &format!("{path}[{i}]"), out);
                }
            }
            (a, b) => {
                // Scalars (and shape-changing mismatches) compare by
                // their serialised text, so `-0.0` vs `0.0` registers.
                let (at, bt) = (
                    serde_json::to_string(a).expect("serialisable"),
                    serde_json::to_string(b).expect("serialisable"),
                );
                if at != bt {
                    out.push(format!("{path}: {at} -> {bt}"));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(writer, stored, "", &mut out);
    out.sort();
    out.join(" | ")
}

/// Build the event for one shape and the `{"type":…,"data":…}` envelope
/// the writer produces for it.
///
/// The envelope comes from `hort_domain::events::stored_payload_envelope`
/// — the production producer that `mappers::serialize_event_data`
/// delegates to and that the append path binds to the column — not from
/// a local re-implementation of the reshape. That is deliberate: this
/// test's question is what the *database* does to the writer's bytes, so
/// anything it computes about the writer has to be what the writer
/// actually computes. A local copy would also quietly measure itself out
/// of the negative-zero normalisation the producer applies.
fn event_and_writer_envelope(
    label: &str,
    metadata: serde_json::Value,
) -> (Uuid, DomainEvent, serde_json::Value) {
    let artifact_id = Uuid::new_v4();
    let sha256: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        .parse()
        .expect("static SHA-256");
    let event = DomainEvent::ArtifactIngested(ArtifactIngested {
        artifact_id,
        repository_id: Uuid::new_v4(),
        name: format!("jsonb-round-trip-{label}"),
        version: Some("1.0.0".into()),
        sha256,
        size_bytes: i64::MAX,
        source: IngestSource::Direct,
        metadata,
        metadata_blob: None,
        upstream_published_at: None,
    });
    let envelope = hort_domain::events::stored_payload_envelope(&event);
    (artifact_id, event, envelope)
}

// ---------------------------------------------------------------------------
// The measurement
// ---------------------------------------------------------------------------

/// Per shape: append it, read the row back, and record whether the
/// stored payload canonicalises to the writer's bytes and whether the
/// production chain verifier calls the untampered row `Ok`.
#[tokio::test]
#[serial(hort_pg_db)]
async fn payload_jsonb_round_trip_is_stable_except_the_recorded_shapes() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let store = PgEventStore::new(pool.clone())
        .await
        .expect("PgEventStore::new must succeed against the migrated pool");
    let reader = PgEventChainReader::new(pool.clone());

    // label -> (canonical bytes moved?, measured delta, verifier broke?)
    let mut measured_unstable: Vec<(String, String)> = Vec::new();
    let mut verifier_breaks: Vec<String> = Vec::new();

    for (label, metadata) in shapes() {
        let (artifact_id, event, writer_envelope) = event_and_writer_envelope(label, metadata);
        let stream = StreamId::artifact(artifact_id);
        let batch = AppendEvents {
            stream_id: stream.clone(),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend::new(event)],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };
        store
            .append(batch)
            .await
            .unwrap_or_else(|e| panic!("{label}: the append path must accept this payload: {e}"));

        let stream_str = stream.to_string();
        let stored: serde_json::Value =
            sqlx::query("SELECT event_data FROM events WHERE stream_id = $1")
                .bind(&stream_str)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("{label}: reading the stored row: {e}"))
                .get("event_data");

        if canonical_text(&writer_envelope) != canonical_text(&stored) {
            measured_unstable.push((label.to_string(), scalar_delta(&writer_envelope, &stored)));
        }

        // Today's production verifier, verbatim: the chain reader's rows
        // through `ChainRow::as_stream_row` into `verify_stream_chain` —
        // what `hort-server verify-event-chain` runs per stream.
        let rows = reader
            .read_stream_chain(&stream_str)
            .await
            .unwrap_or_else(|e| panic!("{label}: chain read: {e}"));
        assert_eq!(rows.len(), 1, "{label}: one appended event, one row");
        let views: Vec<_> = rows.iter().map(ChainRow::as_stream_row).collect();
        match verify_stream_chain(&StreamRows::new(&views)) {
            StreamVerdict::Ok { .. } => {}
            StreamVerdict::Broken {
                at_position,
                reason,
            } => {
                assert_eq!(
                    at_position, 0,
                    "{label}: one-row stream breaks at 0 or not at all"
                );
                verifier_breaks.push(format!("{label} ({reason:?})"));
            }
            other => panic!("{label}: a one-row stream at position 0 cannot be {other:?}"),
        }
    }

    // 1. The unstable set equals the inventory, in both directions.
    let recorded: Vec<&str> = UNSTABLE_SHAPES.iter().map(|u| u.shape).collect();
    let measured: Vec<&str> = measured_unstable.iter().map(|(s, _)| s.as_str()).collect();
    let mut recorded_sorted = recorded.clone();
    recorded_sorted.sort_unstable();
    let mut measured_sorted = measured.clone();
    measured_sorted.sort_unstable();
    assert_eq!(
        recorded_sorted, measured_sorted,
        "the unstable set moved (left: UNSTABLE_SHAPES, right: measured). A new entry \
         means another payload shape stopped surviving the JSONB round trip; a missing \
         one means a shape was repaired and the inventory has to shrink"
    );

    // 2. Per entry, the recorded delta is the measured one. Vacuous
    //    while the inventory is empty, and kept because the inventory is
    //    what shrank: an entry re-added without its real delta fails
    //    here.
    for entry in UNSTABLE_SHAPES {
        let (_, delta) = measured_unstable
            .iter()
            .find(|(s, _)| s == entry.shape)
            .expect("checked above");
        assert_eq!(
            entry.delta, delta,
            "{}: recorded delta is stale ({})",
            entry.shape, entry.mechanism
        );
    }

    // 3. The production chain verifier breaks on exactly the unstable
    //    shapes and on nothing else — so with an empty inventory, on
    //    nothing at all. Two statements in one: the verifier's verdict
    //    agrees with the independently-measured round trip (a shape
    //    whose bytes move is a shape the verifier flags, and the
    //    converse), and every untampered freshly-appended row verifies.
    //    The second is what the chain promises an operator, measured
    //    against a real database rather than reasoned about.
    let mut broke: Vec<&str> = verifier_breaks
        .iter()
        .map(|s| s.split(' ').next().expect("label precedes the reason"))
        .collect();
    broke.sort_unstable();
    assert_eq!(
        recorded_sorted, broke,
        "the chain verifier's verdict and the round-trip measurement disagree \
         (left: UNSTABLE_SHAPES, right: shapes the verifier called Broken: {verifier_breaks:?})"
    );

    // The corpus is not empty and did not shrink into agreement: both
    // statements above are satisfied vacuously by a corpus of nothing,
    // and one of the shapes has to be the one the two float parsers
    // disagree about or the pinned feature goes unmeasured here.
    let labels: Vec<&str> = shapes().iter().map(|(l, _)| *l).collect();
    assert_eq!(
        labels.len(),
        21,
        "the corpus is 21 payload shapes; a shrinking corpus makes this test \
         pass by measuring less (labels: {labels:?})"
    );
    for required in ["inbound--0.0", "rustlit-neg-zero", "rustlit-17digit"] {
        assert!(
            labels.contains(&required),
            "{required} is one of the three shapes this test exists for — the two \
             signed zeros the envelope producer normalises, and the 17-digit float \
             the pinned `float_roundtrip` parser is needed for"
        );
    }
}
