//! Test-only `tracing` capture harness shared by the OCI handler suites.
//!
//! Several OCI invariants live entirely in a log line, and nothing else
//! in the suite reads one: a genuine group-attach `Conflict` must surface
//! at `error!` rather than fold into a silent 500 (`manifests_write`),
//! and the ADR 0039 D6 illegal-state `error!` must fire for a `Rejected`
//! artifact with no rejection on its stream — and must NOT fire for a
//! healthy rejection, which is the whole value of that line (`blobs`).
//! Without a capturing subscriber an edit that drops or inverts either
//! one is green.
//!
//! One implementation, because the machinery is subtle in the same way
//! for every caller (see [`capture_tracing`]), and three suites hand-
//! rolling it would make each copy's correctness a separate question.
//!
//! # Limits
//!
//! - **Only what this test's own subscriber sees.** The capture is a
//!   thread-local default subscriber installed for the duration of the
//!   closure, so an event emitted on another thread never reaches the
//!   buffer. Drive async code on a current-thread runtime's `block_on`
//!   *inside* the closure — a multi-thread runtime's worker loses the
//!   events it emits.
//! - **Events only, never span fields.** `#[tracing::instrument]` puts a
//!   function's arguments on a *span*; this layer implements `on_event`
//!   alone.
//! - **No filtering.** Every event from every crate in the process lands
//!   in the buffer, so select the line under assertion by `target` —
//!   [`events_at`] is that filter — rather than indexing into it.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

/// One captured event.
#[derive(Debug, Clone)]
pub(crate) struct CapturedEvent {
    /// The emitting callsite's `module_path!()` unless the macro
    /// overrode it. Asserting on it is what keeps a claim about *this*
    /// module's logging from passing on a line another module wrote.
    pub(crate) target: String,
    pub(crate) level: tracing::Level,
    /// Every field rendered as `name=value ` pairs — the format string
    /// included, under the name `message`.
    pub(crate) fields: String,
}

/// `Layer` recording every event it is offered into a shared buffer.
#[derive(Clone, Default)]
struct CapturingLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for CapturingLayer
where
    S: tracing::Subscriber,
{
    /// Force per-event re-evaluation instead of letting the global
    /// callsite cache decide once and for all that nobody listens.
    /// `tracing` caches the first `Interest` observed per callsite, and
    /// under libtest's parallelism that first observation can come from
    /// a sibling test firing the same callsite while this test's
    /// thread-local subscriber is not yet installed.
    fn register_callsite(
        &self,
        _meta: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(
        &self,
        _meta: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        true
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(CapturedEvent {
                target: event.metadata().target().to_string(),
                level: *event.metadata().level(),
                fields: visitor.combined,
            });
    }
}

/// Renders each field into the flattened `name=value ` form.
/// `record_debug` is `Visit`'s only required method and every other
/// value type defaults to it, so these two impls cover the whole field
/// taxonomy; the `record_str` override exists only to keep a string
/// value free of `Debug`'s quotes.
#[derive(Default)]
struct MessageVisitor {
    combined: String,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.combined
            .push_str(&format!("{}={:?} ", field.name(), value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.combined
            .push_str(&format!("{}={} ", field.name(), value));
    }
}

/// The one lock serialising captures.
///
/// `tracing` caches per-callsite `Interest` **globally**, so installing a
/// subscriber on one thread while another fires the same callsite races.
/// It is deliberately private and reachable only through
/// [`capture_tracing`]: two independent serialisations do not compose
/// into one order, so a second lock beside this one would let a test
/// holding only that lock run against a test holding only this one.
static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Install, once per process, a global subscriber that returns
/// `Interest::sometimes()` for every callsite.
///
/// This poisons the global callsite-interest cache with `sometimes`,
/// which forces `tracing` to consult the **current** thread-local
/// subscriber on every event instead of trusting a once-cached `Never`
/// from whichever thread reached the callsite first. Without it, a
/// no-op subscriber installed by any earlier test can cache `Never` for
/// these callsites and the per-thread subscriber below never sees them.
fn install_global_passthrough_subscriber() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let global_subscriber = Registry::default().with(CapturingLayer::default());
        // A sibling crate may already hold the global slot; the
        // thread-local re-ask below still gets us the `sometimes()`
        // cache entry.
        let _ = tracing::subscriber::set_global_default(global_subscriber);
    });
}

/// Run `body` with a capturing subscriber installed and return its value
/// alongside every event the subscriber saw.
///
/// `body` is synchronous on purpose: the serialising guard is a
/// `std::sync::Mutex` guard and must not cross an `.await` (clippy's
/// `await_holding_lock` would block the build), so a test drives async
/// code with a current-thread runtime's `block_on` *inside* the closure.
pub(crate) fn capture_tracing<R>(body: impl FnOnce() -> R) -> (R, Vec<CapturedEvent>) {
    install_global_passthrough_subscriber();
    let _serial = TRACING_TEST_MUTEX
        .lock()
        .unwrap_or_else(PoisonError::into_inner);

    let layer = CapturingLayer::default();
    let captured = Arc::clone(&layer.events);
    let subscriber = Registry::default().with(layer);
    let outcome = tracing::subscriber::with_default(subscriber, || {
        // After the thread-local default is in place, force every
        // callsite's interest to be re-evaluated so the layer's
        // `register_callsite` runs before the event under assertion
        // fires.
        tracing::callsite::rebuild_interest_cache();
        body()
    });

    let events = std::mem::take(&mut *captured.lock().unwrap_or_else(PoisonError::into_inner));
    (outcome, events)
}

/// The captured events at `level` emitted from a module whose target
/// starts with `target_prefix`.
///
/// An assertion that a level fired — or did NOT fire — has to say whose
/// line it means: the capture filters nothing, so a bare "no `error!`
/// anywhere" claim would be at the mercy of every other module in the
/// process.
pub(crate) fn events_at<'a>(
    events: &'a [CapturedEvent],
    level: tracing::Level,
    target_prefix: &str,
) -> Vec<&'a CapturedEvent> {
    events
        .iter()
        .filter(|e| e.level == level && e.target.starts_with(target_prefix))
        .collect()
}
