//! `serde_json`'s correctly-rounded float parser is active — asserted by
//! behaviour, not by reading a manifest.
//!
//! The tamper-evident event chain hashes a canonicalisation of the
//! stored payload envelope. At append that envelope's numbers are
//! **printed** by `serde_json`, which emits the shortest text that
//! round-trips to the same `f64`. At verify the same text is **parsed**
//! back out of the `event_data` JSONB column, re-canonicalised and
//! re-hashed. The two ends agree only if the parse is the exact inverse
//! of the print.
//!
//! `serde_json`'s parse is correctly rounded **only** with the
//! `float_roundtrip` feature. Without it `from_str` can land one ulp away
//! from `str::parse`, and printing that neighbouring `f64` produces
//! different text — so the recomputed payload bytes differ from the
//! stored ones and `verify-event-chain` reports a `HashMismatch` on a row
//! nobody touched. Worse, the feature arrived in this workspace
//! *transitively* (`serde_json_canonicalizer` → `sigstore` →
//! `hort-adapters-provenance-sigstore` → `hort-worker`), so it was on for
//! one binary's dependency graph and off for the other's: the hash was a
//! function of the row **and of which binary derived it**. The feature is
//! now declared on the workspace `serde_json` dependency; this test is
//! what keeps it there.
//!
//! **Why a behavioural assertion rather than a manifest grep.**
//! `cfg!(feature = …)` cannot see a *dependency's* features, so the only
//! two options are reading `Cargo.toml` as text or observing what the
//! parser does. A grep would pass on a manifest line cargo's feature
//! resolution never applied (a renamed dependency, a `default-features`
//! change, a second `serde_json` in the graph) and would fail on a build
//! that reaches the same guarantee another way. The parse below is the
//! property the chain actually depends on, measured through the public
//! API against the real resolved dependency.
//!
//! **Why this crate.** Cargo features are additive and unify upward: any
//! build graph containing `hort-domain` resolves `serde_json` with at
//! least the features `hort-domain` asks for. `hort-domain` is the
//! innermost layer (ADR 0008) and every other workspace crate depends on
//! it, so a feature pinned here is pinned for every build of every crate.
//! This test, as a `hort-domain` integration target, therefore observes
//! the **narrowest** resolution in the workspace: if it passes under
//! `cargo test -p hort-domain`, no larger graph can have fewer features.

/// Float texts spanning the shapes a stored payload can carry. Each is
/// used for two independent properties, so they need not be in
/// shortest-round-trip form — one entry deliberately is not.
///
/// `ArtifactIngested.metadata` carries the npm per-version packument
/// block verbatim when it is under the handler's inline threshold, so
/// these are reachable publisher-supplied values, not synthetic ones.
///
/// `123456789.12345679` is the discriminator between the two parsers:
/// without `float_roundtrip` it parses one ulp low (bits
/// `…442550` instead of `…442549`) and reprints as `123456789.1234568`.
const FLOAT_TEXTS: &[&str] = &[
    "123456789.12345679",
    "0.3333333333333333",
    "1.7976931348623157e308",
    "5e-324",
    "1e300",
    "0.1",
    "2.5",
    // 17 significant digits for a double whose shortest form has 16 —
    // included on purpose: a correctly-rounded parse must still land on
    // the same double, and the printer must still emit the shortest
    // form rather than echoing the input.
    "2.2250738585072011e-308",
];

/// The parse is correctly rounded: `serde_json` lands on the same `f64`
/// as `str::parse`, which is Rust's own correctly-rounded parser and
/// independent of `serde_json`'s implementation.
///
/// This is the direct observation of the feature. Bit patterns are
/// compared rather than values, because the two candidates are adjacent
/// doubles and `==` on them is `false` only because they differ — the
/// bits name *which* double, which is what the printer turns into text.
#[test]
fn serde_json_parses_floats_correctly_rounded() {
    for text in FLOAT_TEXTS {
        let parsed: f64 = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("{text}: must parse as a JSON number: {e}"));
        let reference: f64 = text
            .parse()
            .unwrap_or_else(|e| panic!("{text}: must parse as a Rust f64: {e}"));
        assert_eq!(
            parsed.to_bits(),
            reference.to_bits(),
            "{text}: serde_json's parse is not correctly rounded (got {parsed}, \
             str::parse gives {reference}) — the `float_roundtrip` feature is not \
             active on the resolved `serde_json`. Declare it on the workspace \
             `serde_json` dependency; the event chain's recomputed payload bytes \
             depend on the parse being the inverse of the print."
        );
    }
}

/// Text `serde_json` printed reparses to the double it was printed from,
/// and reprints to itself.
///
/// This is the consequence the chain stands on, and it is stated over
/// *printed* text rather than over the corpus entries because that is
/// what a stored payload holds: every number in the `event_data` column
/// was printed by `serde_json` on the append path. A text the printer
/// never emits (a non-shortest-form literal, such as the 17-digit
/// `2.2250738585072011e-308` above) has no round-trip claim to make and
/// asserting one would only measure the corpus.
///
/// The fixed-point form also makes the assertion independent of which
/// double the parse chose: a lossy parser reaches a *different* double,
/// prints its shortest form, and that form reparses and reprints stably
/// too. So this test alone does not pin the feature — it pins that the
/// derivation is reproducible — and
/// `serde_json_parses_floats_correctly_rounded` above is the half that
/// pins which double. Both are needed: correct rounding without a stable
/// reprint would still move the bytes, and a stable reprint of the wrong
/// double is how the two binaries disagreed.
#[test]
fn printed_float_text_is_a_fixed_point_of_parse_then_print() {
    for text in FLOAT_TEXTS {
        let parsed: f64 = serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("{text}: must parse as a JSON number: {e}"));
        let printed = serde_json::to_string(&parsed).expect("an f64 is serialisable");
        let reparsed: f64 = serde_json::from_str(&printed)
            .unwrap_or_else(|e| panic!("{printed}: serde_json's own output must parse: {e}"));
        assert_eq!(
            reparsed.to_bits(),
            parsed.to_bits(),
            "{text}: printed as {printed}, which parses back to a different double \
             — the printer's output does not identify the value it came from"
        );
        let reprinted = serde_json::to_string(&reparsed).expect("an f64 is serialisable");
        assert_eq!(
            reprinted, printed,
            "{text}: printed as {printed} but reprints as {reprinted} — a stored \
             payload carrying it re-canonicalises to different bytes than it was \
             hashed with"
        );
    }
}

/// The discriminator text is itself a fixed point: it is exactly what
/// `serde_json` prints for the double a correctly-rounded parse of it
/// yields.
///
/// Pins the corpus rather than the parser. `FLOAT_TEXTS`'s first entry is
/// load-bearing — it is the one text the two parsers disagree on — and a
/// future edit that "tidied" it into a shorter literal both parsers agree
/// about would leave both tests above green while measuring nothing. The
/// `2.2250738585072011e-308` entry proves the corpus also holds a
/// non-printed shape, so neither property can be satisfied by a corpus of
/// one kind.
#[test]
fn the_discriminator_text_is_what_the_printer_emits() {
    let discriminator = FLOAT_TEXTS[0];
    let parsed: f64 = serde_json::from_str(discriminator).expect("a JSON number");
    assert_eq!(
        serde_json::to_string(&parsed).expect("serialisable"),
        discriminator,
        "the corpus's discriminator must be the printer's own output for the \
         correctly-rounded parse of itself, or the two parsers do not disagree \
         about it and the guard measures nothing"
    );
    let non_shortest = "2.2250738585072011e-308";
    assert!(
        FLOAT_TEXTS.contains(&non_shortest),
        "the corpus must keep a text the printer never emits, so the fixed-point \
         property is not satisfied vacuously"
    );
    let parsed_long: f64 = serde_json::from_str(non_shortest).expect("a JSON number");
    assert_ne!(
        serde_json::to_string(&parsed_long).expect("serialisable"),
        non_shortest,
        "{non_shortest} is expected NOT to be the printer's output for its own value"
    );
}
