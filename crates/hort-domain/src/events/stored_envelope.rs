//! The one producer of an event's **stored payload envelope** — the
//! `{"type":…,"data":…}` value the `events.event_data` column holds and
//! the tamper-evident chain hashes.
//!
//! There used to be two: the adapter's write path built the envelope to
//! `INSERT` it, and the chain built its own copy to hash. The second was
//! documented as "a faithful mirror" of the first, which is the problem —
//! a mirror is a second voice, and the chain's whole claim is that the
//! bytes it hashed are the bytes the row holds. One function, called by
//! both, makes that true by construction instead of by agreement:
//! `hort-adapters-postgres::mappers::serialize_event_data` delegates here
//! for the value it binds, and the append path passes that same value
//! into [`ChainInput::payload`](super::ChainInput::payload). Verification
//! does not call this at all — it hashes the payload read back from the
//! column.
//!
//! It lives in `hort-domain` because that is the only layer both callers
//! can reach (ADR 0008: the adapter depends on the domain, never the
//! reverse). The *shape* is a persistence concern, but it is one the
//! domain's chain already had to know in order to hash it.

use super::DomainEvent;

/// The stored payload envelope for `event`: serde's externally-tagged
/// enum form re-shaped into `{"type": event_type(), "data": {fields}}`,
/// with negative zero normalised away (see
/// [`normalise_signed_zero`]).
///
/// Infallible: it serialises a typed `DomainEvent`, which has no maps
/// with non-string keys and no `Serialize` impl that can error, so the
/// append path gains no new fallible step.
pub fn stored_payload_envelope(event: &DomainEvent) -> serde_json::Value {
    let raw = serde_json::to_value(event).expect("DomainEvent is always serializable");
    // The stored `type` is `event_type()`; the key serde actually emitted
    // — and so the key to strip — is `serde_variant_key()`. The two
    // differ only for the `RetentionPolicyChanged` wrapper, whose
    // `event_type()` is the inner-discriminated
    // `RetentionPolicyCreated`/`…Updated`/`…Archived`/`…Evaluated`.
    // Stripping by `event_type()` would remove a key that is not there
    // and silently null that wrapper's payload.
    reshape_to_envelope(event.event_type(), event.serde_variant_key(), raw)
}

/// The reshape, taking the raw serde value, so both the
/// object-with-key path and the two fallbacks are directly
/// unit-testable — `hort-domain` is the 100%-coverage tier and a
/// fallback has to be exercised, not asserted unreachable.
fn reshape_to_envelope(
    event_type: &str,
    serde_key: &str,
    raw: serde_json::Value,
) -> serde_json::Value {
    let payload = match raw {
        serde_json::Value::Object(mut map) => {
            // Missing-key arm: a `Null` payload. Reached only if serde's
            // externally-tagged representation stopped emitting the
            // variant key, which would be a serde-version change rather
            // than a data case.
            map.remove(serde_key).unwrap_or(serde_json::Value::Null)
        }
        // Non-object arm: pass the value through as the payload. Also
        // only reachable if serde's externally-tagged enum
        // representation changed; passing it through keeps the stored
        // row and the hashed bytes identical whatever it produced.
        other => other,
    };
    normalise_signed_zero(serde_json::json!({ "type": event_type, "data": payload }))
}

/// Rewrite every negative zero in the envelope as positive zero.
///
/// `jsonb` stores numbers as `numeric`, and `numeric` has no signed
/// zero: a payload carrying `-0.0` is stored as `0.0`, and the sign is
/// gone before the row exists — nothing on the client can recover it.
/// So a writer that hashed `-0.0` had attested bytes the row does not
/// hold, and `verify-event-chain` reported `HashMismatch` on an
/// untouched row. Measured, not theoretical: `ArtifactIngested.metadata`
/// carries an npm publisher's per-version packument block verbatim, so
/// `-0.0` is client-reachable.
///
/// Normalising here rather than refusing the publish loses nothing that
/// is not already lost at `INSERT` — JSON gives a zero's sign no
/// meaning, and no consumer of a payload can observe it — and it makes
/// the writer and the row agree by construction. It is applied at the
/// single point the envelope is produced, so the value that is hashed
/// and the value that is written are the same object.
///
/// Scope is deliberately this one value class. A transformation that
/// changed what a payload *means* would be a different thing entirely:
/// the chain may normalise away a distinction the store cannot keep, and
/// must never normalise away one it can.
fn normalise_signed_zero(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, normalise_signed_zero(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(normalise_signed_zero).collect())
        }
        serde_json::Value::Number(n) => match n.as_f64() {
            // `is_sign_negative` rather than `< 0.0`: the whole point is
            // the value that compares equal to positive zero. Integer
            // zeros reach `as_f64() == 0.0` too and are left alone —
            // their `is_sign_negative` is false, and `Number`'s integer
            // and float representations print differently (`0` vs `0.0`),
            // so rebuilding one as the other would move bytes Postgres
            // keeps.
            Some(f) if f == 0.0 && f.is_sign_negative() => {
                serde_json::Value::Number(serde_json::Number::from_f64(0.0).expect("0.0 is finite"))
            }
            _ => serde_json::Value::Number(n),
        },
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_with_the_serde_key_becomes_the_stored_envelope() {
        let raw = serde_json::json!({ "ArtifactIngested": {"x": 1} });
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw),
            serde_json::json!({ "type": "ArtifactIngested", "data": {"x": 1} })
        );
    }

    /// The `RetentionPolicyChanged` wrapper is the one variant whose
    /// stored `type` (discriminated) differs from the serde key: the key
    /// is stripped, the discriminated `type` is stamped.
    #[test]
    fn retention_wrapper_strips_the_serde_key_and_keeps_the_discriminated_type() {
        let raw = serde_json::json!({ "RetentionPolicyChanged": {"Created": {"id": "x"}} });
        assert_eq!(
            reshape_to_envelope("RetentionPolicyCreated", "RetentionPolicyChanged", raw),
            serde_json::json!({
                "type": "RetentionPolicyCreated",
                "data": {"Created": {"id": "x"}}
            })
        );
    }

    #[test]
    fn object_without_the_serde_key_falls_back_to_a_null_payload() {
        let raw = serde_json::json!({ "SomethingElse": {"x": 1} });
        assert_eq!(
            reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw),
            serde_json::json!({ "type": "ArtifactIngested", "data": serde_json::Value::Null })
        );
    }

    #[test]
    fn a_non_object_raw_value_passes_through_as_the_payload() {
        for raw in [
            serde_json::Value::String("unexpected".into()),
            serde_json::Value::Number(serde_json::Number::from(42)),
            serde_json::Value::Bool(false),
            serde_json::Value::Array(vec![serde_json::json!(1)]),
            serde_json::Value::Null,
        ] {
            assert_eq!(
                reshape_to_envelope("ArtifactIngested", "ArtifactIngested", raw.clone()),
                serde_json::json!({ "type": "ArtifactIngested", "data": raw })
            );
        }
    }

    /// Negative zero is normalised wherever it sits — at the top of the
    /// payload, nested in an object, inside an array — and the
    /// comparison is on **text**, because `serde_json::Value`'s
    /// `PartialEq` compares numbers with IEEE `==`, under which
    /// `-0.0 == 0.0` is `true`. A `Value` assertion here would pass
    /// without the normalisation.
    /// The expected text below is key-sorted because `serde_json::Map`
    /// is a `BTreeMap` without the `preserve_order` feature (which this
    /// workspace does not enable), so a `Value`'s keys serialise in
    /// lexicographic order whatever order they were inserted in.
    #[test]
    fn negative_zero_is_normalised_everywhere_in_the_payload() {
        let raw = serde_json::json!({
            "E": {
                "top": -0.0,
                "nested": { "n": -0.0 },
                "in_array": [-0.0, 1.5, {"deep": -0.0}],
            }
        });
        let envelope = reshape_to_envelope("E", "E", raw);
        let text = serde_json::to_string(&envelope).expect("serialisable");
        assert!(
            !text.contains("-0.0"),
            "every negative zero must be normalised, got {text}"
        );
        assert_eq!(
            text,
            r#"{"data":{"in_array":[0.0,1.5,{"deep":0.0}],"nested":{"n":0.0},"top":0.0},"type":"E"}"#
        );
    }

    /// What normalisation must NOT touch: a positive zero float stays a
    /// float, an integer zero stays an integer, and every other number
    /// is passed through bit-for-bit — including the `u64`/`i64` extremes
    /// a round trip through `f64` would destroy.
    #[test]
    fn every_other_number_passes_through_unchanged() {
        let raw = serde_json::json!({
            "E": {
                "float_zero": 0.0,
                "int_zero": 0,
                "neg_int": -1,
                "u64_max": u64::MAX,
                "i64_min": i64::MIN,
                "tiny_negative": -5e-324,
                "seventeen_digits": 123456789.12345679_f64,
            }
        });
        let envelope = reshape_to_envelope("E", "E", raw.clone());
        assert_eq!(
            serde_json::to_string(&envelope).expect("serialisable"),
            format!(
                r#"{{"data":{},"type":"E"}}"#,
                serde_json::to_string(&raw["E"]).expect("serialisable")
            ),
            "normalisation must be the identity on every number that is not a negative zero"
        );
    }

    /// Strings and other scalars are not number-shaped and must be left
    /// alone even when they *spell* a negative zero — the normalisation
    /// is on values, not on text.
    #[test]
    fn a_string_spelling_negative_zero_is_untouched() {
        let raw = serde_json::json!({ "E": { "s": "-0.0", "b": true, "nil": null } });
        let envelope = reshape_to_envelope("E", "E", raw);
        assert_eq!(
            serde_json::to_string(&envelope).expect("serialisable"),
            r#"{"data":{"b":true,"nil":null,"s":"-0.0"},"type":"E"}"#
        );
    }

    /// The public entry point goes through a real `DomainEvent`: the
    /// envelope's `type` is the stored `event_type()` and `data` is the
    /// variant's fields, not serde's externally-tagged wrapper.
    #[test]
    fn the_public_producer_emits_the_stored_shape_for_a_real_event() {
        let event = DomainEvent::ArtifactRejected(crate::events::ArtifactRejected {
            artifact_id: uuid::Uuid::nil(),
            rejected_by: crate::events::RejectionReason::Scanner,
            reason: "CVE-2026-0001".into(),
        });
        let envelope = stored_payload_envelope(&event);
        assert_eq!(envelope["type"], serde_json::json!("ArtifactRejected"));
        assert_eq!(
            envelope["data"]["reason"],
            serde_json::json!("CVE-2026-0001")
        );
        assert!(
            envelope.get(event.serde_variant_key()).is_none(),
            "serde's externally-tagged key must not survive into the stored envelope"
        );
    }
}
