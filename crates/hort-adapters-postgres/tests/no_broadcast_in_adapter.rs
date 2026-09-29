//! Layering guard: `hort-adapters-postgres` holds no broadcast channel.
//!
//! Notification fan-out is an application-layer concern. The only sender
//! in the process belongs to `hort_app::event_store_publisher::EventStorePublisher`,
//! which wraps the `EventStore` port from *above* — so the dependency
//! points inward, adapter → port → application, and never back out
//! (ADR 0008). A `broadcast::Sender` inside this crate would invert that,
//! and it would do so for a reason that sounds good in review: the
//! transactional write path (`PgEventStore::append_in_tx`, reached through
//! the lifecycle ports) sits below the publisher, so "just send after
//! commit, from the adapter" looks like the obvious way to reach a
//! subscriber. It is the anti-pattern ADR 0061 exists to name: delivery is
//! driven by *reads* of the event store, so no write path needs to
//! announce itself at all.
//!
//! # Why a source scan, and why the behavioural test is not enough
//!
//! `tests/event_delivery_visibility.rs`'s
//! `transactional_append_is_absent_from_the_broadcast_channel` asserts the
//! same rule end-to-end, and it is a real test — its control assertion
//! proves the channel works before the negative assertion runs. But it
//! constructs the lifecycle port over a `PgEventStore` that has no sender
//! in reach, so it can only observe that *this* wiring does not send. A
//! sender reached through a setter, a lazily-initialised `OnceLock`, or a
//! constructor the test does not call would leave it green. The scan
//! observes the crate instead of an instance of it, which is the level the
//! rule is stated at. Both are kept: the scan says the type is absent, the
//! behavioural test says the property holds for the wiring that ships.
//!
//! # What counts as a hit
//!
//! A line outside a Rust line comment containing the path prefix
//! `broadcast::` — `broadcast::Sender`, `broadcast::channel`,
//! `use tokio::sync::broadcast::…`, all of them. The trailing `::` is what
//! distinguishes naming the module from naming the word, the same
//! discrimination `hort-app/tests/no_bcrypt.rs` makes with `bcrypt::`: a
//! test fixture calling `EventStorePublisher::without_broadcast(store)` is
//! asserting the *absence* of a sender and must keep compiling.
//!
//! Doc comments in this crate legitimately explain why the sender lives
//! elsewhere, and those must stay readable — the compiler-relevant
//! question is whether code names the type. Block comments are not
//! stripped: a regression smuggled in through `/* */` would be a
//! self-evidently bad-faith change, and the same reasoning is recorded in
//! `no_bcrypt.rs`.

use std::fs;
use std::path::{Path, PathBuf};

/// Every `.rs` file under this crate's `src/`.
fn adapter_sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut out,
    );
    assert!(
        !out.is_empty(),
        "the guard found no sources to scan, which would make it vacuous"
    );
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Is this line a Rust line comment (`//`, `///`, `//!`)?
fn is_line_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

#[test]
fn the_postgres_adapter_holds_no_broadcast_channel() {
    let mut hits: Vec<String> = Vec::new();
    for path in adapter_sources() {
        let source = fs::read_to_string(&path).expect("adapter source is readable");
        for (n, line) in source.lines().enumerate() {
            if is_line_comment(line) {
                continue;
            }
            if line.contains("broadcast::") {
                hits.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "hort-adapters-postgres must not reference a broadcast channel — notification \
         fan-out belongs to hort_app::event_store_publisher (ADR 0008/0061), and a \
         post-commit send from the adapter is the shape that inverts the dependency. \
         Delivery is driven by reads of the event store, so no write path here needs to \
         announce itself. Found:\n{}",
        hits.join("\n")
    );
}

/// The guard must be able to fail. If the scan or the comment filter ever
/// stops seeing code lines, `hits.is_empty()` above becomes vacuously true
/// and the rule is enforced by nothing.
#[test]
fn the_scan_sees_code_lines_and_skips_comments() {
    assert!(is_line_comment(
        "   /// the broadcast sender lives in hort-app"
    ));
    assert!(is_line_comment("//! broadcast::Sender"));
    assert!(!is_line_comment("let (tx, _rx) = broadcast::channel(16);"));
    // The discrimination the `::` buys: a sender is a hit, asserting the
    // absence of one is not.
    assert!("let (tx, _rx) = broadcast::channel(16);".contains("broadcast::"));
    assert!(!"EventStorePublisher::without_broadcast(store)".contains("broadcast::"));

    // And the corpus really is this crate's source: a token that must be
    // there is.
    let found_real_code = adapter_sources().iter().any(|path| {
        fs::read_to_string(path)
            .expect("adapter source is readable")
            .lines()
            .any(|line| !is_line_comment(line) && line.contains("impl EventStore for PgEventStore"))
    });
    assert!(
        found_real_code,
        "the scanned corpus does not contain the adapter's own EventStore impl, so the \
         guard is not looking at what it claims to"
    );
}
