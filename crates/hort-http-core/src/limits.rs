//! Inbound-adapter request-shape limits.
//!
//! Centralises the body-size, multipart-field, and route-parameter caps
//! applied by every format handler. Consolidating the constants here
//! keeps the ceilings in one place instead of scattered per-handler
//! literals. The rationale behind each number is documented on the
//! constant itself.
//!
//! One operator value here is not a cap at all: a configured publish
//! body limit of `0` means "refuse all publishes". The size-versus-kill-
//! switch split lives in [`cargo_publish_body_limit`] and the refusal
//! itself in [`refuse_publishes_when_disabled`] — one definition each,
//! applied once per publish subtree.

use axum::body::Body;
use axum::extract::{FromRequestParts, Path, RawPathParams, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use serde::de::DeserializeOwned;

/// Default per-publish body-size ceiling applied to formats that don't
/// declare their own override (npm, PyPI and Maven today). 300 MiB —
/// generous enough for every legitimate tarball shape across the formats
/// that share this default, tight enough to reject runaway uploads.
///
/// Overridable at runtime via the `HORT_PUBLISH_BODY_MAX_SIZE`
/// environment variable, parsed in `hort-server::config::Config`. The
/// parsed override (or the default) is threaded through `AppContext`
/// and consumed by each format's route builder — no handler reads the
/// env var directly.
pub const DEFAULT_PUBLISH_BODY_LIMIT: usize = 300 * 1024 * 1024;

/// Fixed per-publish body-size ceiling for Cargo. Cargo crates are
/// meaningfully smaller than Python wheels or npm tarballs in practice,
/// so a tighter 200 MiB ceiling is appropriate. A *size* set through
/// `HORT_PUBLISH_BODY_MAX_SIZE` does not move it — that override ties to
/// the shared 300 MiB default and changing cargo's ceiling silently
/// alongside npm/PyPI would surprise operators who tuned the shared
/// variable for Python wheels. A future item can introduce a
/// cargo-specific override if operational data calls for one.
///
/// Zero is the one value that does reach Cargo, because zero is not a
/// different ceiling but the refuse-all-publishes kill switch, which has
/// to close every publish surface to be worth anything. The split
/// between the two meanings lives in exactly one place —
/// [`cargo_publish_body_limit`] — and the refusal zero produces in
/// another, [`refuse_publishes_when_disabled`]. Only the *size* meaning
/// reaches `DefaultBodyLimit`.
pub const CARGO_PUBLISH_BODY_LIMIT: usize = 200 * 1024 * 1024;

/// Resolve Cargo's effective publish body limit from the shared
/// effective limit — the parsed `HORT_PUBLISH_BODY_MAX_SIZE`, or
/// [`DEFAULT_PUBLISH_BODY_LIMIT`] when the operator set nothing.
///
/// Zero propagates unchanged: an operator who disables publishing during
/// an incident must get every publish surface closed, and a kill switch
/// that leaves one format open is worse than none because it changes
/// what the operator does next — they stop looking for another way to
/// halt writes. Any other value is a *size*, and Cargo keeps
/// [`CARGO_PUBLISH_BODY_LIMIT`] (see that constant for why).
///
/// This function resolves *which number* Cargo's route builder gets;
/// what a zero one then does is [`refuse_publishes_when_disabled`]'s
/// job.
///
/// This function is the single site of that rule: the composition root
/// calls it and hands the result to Cargo's route builder, so no call
/// site re-derives the special case.
pub fn cargo_publish_body_limit(shared_limit: usize) -> usize {
    if shared_limit == 0 {
        0
    } else {
        CARGO_PUBLISH_BODY_LIMIT
    }
}

// ---------------------------------------------------------------------------
// The publish kill switch — refusing the publish, not merely its body
// ---------------------------------------------------------------------------

/// Does a request with this method carry a publish, and so fall under
/// the kill switch?
///
/// Written as the **pass** list rather than the refuse list so the
/// switch is fail-closed: a mutating method registered on a publish
/// route later is held until someone comes here and deliberately opens
/// it, rather than slipping through a refuse list nobody updated.
///
/// The reach is wider than the methods a route actually registers, and
/// that is measured rather than assumed: `Router::route_layer` wraps a
/// matched route's whole `MethodRouter` — including the `405` fallback
/// it would answer an unregistered method with — so a `PATCH` at a
/// `GET`-only path inside a publish subtree is held as well (pinned by
/// `a_mutating_method_no_route_registers_is_still_held`). While the
/// switch is on, such a method trades its `405` for the hold. That is
/// the fail-closed direction, and `OPTIONS` is on the pass list below,
/// so preflight is unaffected.
///
/// - `GET` / `HEAD` / `OPTIONS` carry no publish and pass untouched.
///   This is why the guard discriminates by method and never by route
///   tree: a hort that stopped *serving* artifacts because publishing
///   was switched off would be a worse failure than the one the switch
///   exists to produce.
/// - `DELETE` is not a publish either, and holding it would strand work
///   a client then cannot clean up — the OCI
///   `DELETE /v2/<name>/blobs/uploads/<uuid>` cancel is how a client
///   releases an upload session it can no longer finish. The knob's
///   contract is "refuse publishes"; removal is governed elsewhere.
fn method_carries_a_publish(method: &Method) -> bool {
    !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "DELETE")
}

/// The refusal a hosted-format publish receives while the kill switch
/// is on: `503 Service Unavailable`, JSON body, **no `Retry-After`**.
///
/// `503` is this project's recorded answer for "not serving this right
/// now" — the download path answers a quarantine hold the same way,
/// and `409` is a recorded anti-pattern there because proxies cache
/// it. It also reads as what this is: an administrative hold, not a
/// client error and not an authorization failure. `413 Payload Too
/// Large` stays reserved for a body that genuinely exceeds a
/// configured non-zero ceiling; answering a zero-byte request with it
/// tells the client something untrue.
///
/// No `Retry-After`: the quarantine hold carries one because it knows
/// its own deadline, and this hold has none — it ends when an operator
/// changes the configuration. A fabricated interval would be a lie a
/// well-behaved client then acts on, so the body's message carries the
/// "no reopen time is known" part instead of a header implying
/// otherwise.
pub fn publish_disabled_response() -> Response {
    const BODY: &str = concat!(
        r#"{"error":"publishing is disabled on this server","#,
        r#""detail":"an operator disabled publishing; it reopens only by "#,
        r#"configuration change, so no reopen time is known and no "#,
        r#"Retry-After is sent"}"#
    );
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(BODY))
        .expect("static response")
}

/// Per-subtree factory for the refusal
/// [`refuse_publishes_when_disabled`] serves.
///
/// Only the body shape varies by subtree. The four hosted-format
/// routers pass [`publish_disabled_response`]; `hort-http-oci` passes
/// its own so the `/v2/*` surface answers in the `errors`-array
/// envelope the OCI Distribution spec requires of an error response —
/// a client that parses that envelope (docker, the containerd
/// resolver) then surfaces the message, where the generic
/// `{"error":...}` body would reach the operator as nothing better
/// than "unexpected status: 503".
///
/// A plain `fn` pointer, not a boxed closure: `Response` is not
/// `Clone`, so the middleware needs a factory rather than a prebuilt
/// response, and a `fn` pointer is `Copy` — which is what lets the
/// layer clone its state per request for free.
pub type PublishRefusal = fn() -> Response;

/// Refuse every publish on `router` with `refusal()` when `limit` is
/// zero. This is the one definition of the
/// `HORT_PUBLISH_BODY_MAX_SIZE=0` kill switch; each publish subtree
/// applies it once.
///
/// Zero is not a smaller ceiling, it is "refuse all publishes" — and
/// before this guard the refusal was left to `DefaultBodyLimit::max(0)`,
/// which rejects a body that has bytes in it and admits one that does
/// not. Maven's PUT has no envelope that could fail on empty input, so
/// a zero-byte `.jar` was *ingested* while the switch was on: an
/// artifact row, an `ArtifactIngested`, a quarantine timer and a scan
/// job, out of a gate the operator believed shut. Cargo, npm and PyPI
/// refused the same request only as a side effect of their payload
/// grammars rejecting an empty envelope, which is a property of those
/// grammars and never a promise of the limit.
///
/// A non-zero `limit` returns `router` untouched. An over-size body
/// against a configured ceiling is a different answer (`413`) reached
/// through a different mechanism (`DefaultBodyLimit`), and the two must
/// not collapse into one path that answers both alike.
///
/// `route_layer`, not `layer`: the guard must wrap the subtree's routes
/// and not its fallback, so a request to an unmatched path still
/// answers `404` rather than reporting a publish hold.
pub fn refuse_publishes_when_disabled<S>(
    router: Router<S>,
    limit: usize,
    refusal: PublishRefusal,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if limit != 0 {
        return router;
    }
    router.route_layer(axum::middleware::from_fn_with_state(
        refusal,
        publish_kill_switch,
    ))
}

/// The guard [`refuse_publishes_when_disabled`] attaches: answer every
/// publish-carrying method with the subtree's refusal, pass everything
/// else to the inner service.
///
/// Attached only when the configured limit is zero, so reaching this
/// function at all already means the switch is on — there is no limit
/// comparison here, and the predicate is not written a second time.
///
/// Emits `tracing::warn!` per refused publish, matching the
/// load-shed 503's level: the hold is deliberate, so `error!` would be
/// wrong, but an operator debugging "why do my publishes fail" has to
/// find it in a default log configuration. The message names the env
/// var because that is the only thing that turns the hold off.
async fn publish_kill_switch(
    State(refusal): State<PublishRefusal>,
    request: Request,
    next: Next,
) -> Response {
    if method_carries_a_publish(request.method()) {
        tracing::warn!(
            method = %request.method(),
            "refusing a publish: HORT_PUBLISH_BODY_MAX_SIZE is 0 on this server"
        );
        return refusal();
    }
    next.run(request).await
}

/// Maximum number of multipart fields a single PyPI upload may contain
/// before the handler rejects with `400 Bad Request`. 100 is well above
/// anything `twine` sends in practice (a typical publish has ~6 fields:
/// `name`, `version`, `:action`, `content`, plus 1–3 metadata fields)
/// and below any value that would exhaust memory even if every field
/// body were harvested. Emits a `tracing::warn!` on reject — client
/// misbehaviour, not infrastructure failure.
pub const MAX_MULTIPART_FIELDS: usize = 100;

/// Maximum byte length of a single axum route parameter (e.g. `repo_key`,
/// a package name, a filename segment).
///
/// 512 bytes comfortably admits every legitimate identifier across the
/// package-format universe we serve: PyPI package names are PEP 508-
/// bounded to sensible lengths, npm package names max out at 214 chars
/// per the npm spec, cargo crate names are ≤ 64 chars, and semver-ish
/// versions rarely exceed 64. The cap exists to bound the downstream
/// work an attacker can force per URL segment — a 100 KiB `:name` path
/// parameter, even if it never matches a real artifact, still forces
/// every intervening layer (URL parsing, extraction, logging) to move
/// bytes for no business purpose.
///
/// Hard-coded constant — NOT an operator knob. This is a hardening
/// limit, not a capacity setting; exposing an env override dilutes the
/// guarantee and invites an operator to "fix" a legitimate rejection by
/// raising the cap rather than investigating why a client is sending
/// kilobyte-long identifiers.
pub const MAX_ROUTE_PARAM_BYTES: usize = 512;

/// Validate a single axum `Path<...>` value against [`MAX_ROUTE_PARAM_BYTES`].
///
/// Returns `Ok(())` when the parameter is within the cap, or a boxed
/// pre-shaped `400 Bad Request` [`Response`] when it exceeds it. The
/// response body shape mirrors the existing 400-body convention used by
/// the format handlers (`{"error": "...", "parameter": "..."}`) so
/// native clients that surface server error bodies get a legible
/// reason. The response is boxed to keep the `Result` small — same
/// pattern as `handlers::pypi::AuthzReject`.
///
/// # Bytes, not chars
///
/// The check is `value.len()` — i.e. UTF-8 byte length. Using
/// `chars().count()` would let an attacker inflate memory pressure by a
/// factor of 4 per-segment with multi-byte code points while still
/// passing a char-count cap. Bytes is the DoS-relevant unit.
///
/// # Observability
///
/// Emits `tracing::warn!` on rejection (client misbehaviour, not an
/// infrastructure failure — no `error!`, no `#[instrument(err)]`).
pub fn validate_route_param(name: &str, value: &str) -> Result<(), Box<Response>> {
    if value.len() <= MAX_ROUTE_PARAM_BYTES {
        return Ok(());
    }
    tracing::warn!(
        parameter_name = %name,
        actual_bytes = %value.len(),
        max_bytes = %MAX_ROUTE_PARAM_BYTES,
        "route parameter exceeds length cap"
    );
    let body = format!(r#"{{"error":"route parameter too long","parameter":"{name}"}}"#);
    Err(Box::new(
        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("static response"),
    ))
}

// ---------------------------------------------------------------------------
// BoundedPath<T> — Path<T> + MAX_ROUTE_PARAM_BYTES enforcement
// ---------------------------------------------------------------------------

/// Axum `Path<T>` extractor that also enforces [`MAX_ROUTE_PARAM_BYTES`]
/// on every captured route segment before the handler body runs.
///
/// Handlers that previously paired `Path<(String, String, ...)>` with a
/// stanza of `validate_route_param(...)` calls declare `BoundedPath<...>`
/// instead — the validation runs inside the extractor, and the handler
/// body starts with a guarantee that every path segment is within cap.
///
/// ## Error shape
///
/// On violation the extractor short-circuits with the same `400 Bad
/// Request` + `{"error":"route parameter too long","parameter":"<name>"}`
/// body that [`validate_route_param`] produces — native clients that
/// match on the JSON body see no wire-format change. The `<name>` value
/// is the route-template capture name (e.g. `"repo_key"`, `"project"`,
/// `"filename"`) — axum populates the map from the route template, so
/// names remain meaningful without callers having to declare them a
/// second time.
///
/// ## Parameter-name source
///
/// Names come from axum's own route-template parser via the
/// `Path<HashMap<String, String>>` pre-pass. This is why the error body's
/// `parameter` field remains byte-identical to the pre-refactor handler
/// sites — those sites passed string literals that mirrored the route
/// template (`:repo_key` ↦ `"repo_key"`), and the HashMap key is the
/// same string.
///
/// ## Ordering
///
/// The extractor runs the length check against every map entry before
/// attempting the typed `Path<T>` extraction. If multiple segments are
/// over-cap, the caller sees the first one HashMap iteration surfaces.
/// That is non-deterministic across HashMap insertion order, but any
/// single segment over cap is already a client bug — the response still
/// carries a valid `parameter` label naming one real offender, so
/// operators retain the signal they need. Pre-refactor handlers also
/// short-circuited on the first over-cap segment (in source order), so
/// no caller relied on a specific parameter name being reported when
/// multiple were over-cap.
#[derive(Debug, Clone)]
pub struct BoundedPath<T>(pub T);

impl<T> BoundedPath<T> {
    /// Unwrap to the inner extracted value — mirrors axum's
    /// `Path::into_inner`-style ergonomics for call sites that need to
    /// move the payload out of the wrapper.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T, S> FromRequestParts<S> for BoundedPath<T>
where
    T: DeserializeOwned + Send + 'static,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // First pass: RawPathParams. Axum's low-level accessor yields
        // the captured `(name, value)` pairs directly from the matched
        // route template without forcing any deserialization shape, so
        // it succeeds on every route that has captures — no
        // HashMap-extraction-specific failure mode that could silently
        // bypass the length check. Routes with zero captures yield an
        // empty iterator; we skip the loop and fall through to the
        // typed pass for the benign no-op case.
        //
        // Capture names match the route template (`:repo_key` →
        // `"repo_key"`, …) — byte-identical to the pre-refactor
        // `validate_route_param(name, ...)` argument.
        match RawPathParams::from_request_parts(parts, state).await {
            Ok(raw) => {
                for (name, value) in &raw {
                    if let Err(resp) = validate_route_param(name, value) {
                        return Err(*resp);
                    }
                }
            }
            Err(err) => {
                // The only documented RawPathParams rejection is
                // percent-decoded UTF-8 failure on a capture. Surface
                // it as the caller's typed rejection would have — 400
                // with axum's own body. Do NOT fall through silently
                // (the pre-Item-7 refactor's implicit guarantee was
                // "every captured segment is checked OR the request
                // fails"; this arm preserves that).
                return Err(err.into_response());
            }
        }

        // Second pass: typed extraction in the caller's declared shape.
        // Axum stores path captures in `parts.extensions` and the first
        // extraction does not consume them, so this succeeds with the
        // same bytes the caller's signature expects.
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(err) => Err(err.into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;

    // -- cargo_publish_body_limit ---------------------------------------------------

    #[test]
    fn cargo_keeps_its_own_ceiling_when_the_shared_limit_is_the_default() {
        // Operator set nothing: the composition root resolves the shared
        // 300 MiB default, and cargo stays on its own 200 MiB ceiling.
        assert_eq!(
            cargo_publish_body_limit(DEFAULT_PUBLISH_BODY_LIMIT),
            CARGO_PUBLISH_BODY_LIMIT
        );
    }

    #[test]
    fn cargo_keeps_its_own_ceiling_under_a_non_zero_size_override() {
        // The recorded decision, pinned rather than merely commented: a
        // shared size override — larger or smaller than cargo's own
        // ceiling — never moves cargo's ceiling.
        assert_eq!(
            cargo_publish_body_limit(1024 * 1024 * 1024),
            CARGO_PUBLISH_BODY_LIMIT
        );
        assert_eq!(cargo_publish_body_limit(1024), CARGO_PUBLISH_BODY_LIMIT);
    }

    #[test]
    fn zero_shared_limit_is_the_kill_switch_and_reaches_cargo() {
        // Zero is not a smaller ceiling; it is "refuse all publishes",
        // and it propagates so the switch closes cargo too.
        assert_eq!(cargo_publish_body_limit(0), 0);
    }

    #[test]
    fn accepts_value_under_cap() {
        // 1 byte below the ceiling — the common case.
        let v = "a".repeat(MAX_ROUTE_PARAM_BYTES - 1);
        assert!(validate_route_param("repo_key", &v).is_ok());
    }

    #[test]
    fn accepts_value_at_cap_boundary() {
        // Exactly 512 bytes — the "<= cap" branch. Guards against an
        // off-by-one that would reject the boundary.
        let v = "a".repeat(MAX_ROUTE_PARAM_BYTES);
        assert_eq!(v.len(), MAX_ROUTE_PARAM_BYTES);
        assert!(validate_route_param("repo_key", &v).is_ok());
    }

    #[tokio::test]
    async fn rejects_value_one_byte_over_cap() {
        // 513 bytes — the first value that must reject. Proves the
        // comparator is `>` not `>=`.
        let v = "a".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let resp = *validate_route_param("package_name", &v).unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "package_name");
    }

    #[test]
    fn rejects_kilobyte_value() {
        // 1 KiB — the "attacker-class" input the cap defends against.
        let v = "x".repeat(1024);
        let resp = validate_route_param("crate_name", &v).unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn cap_is_bytes_not_chars() {
        // Ensures the comparator counts bytes, not chars. A 200-char
        // string of 4-byte code points is 800 bytes — over the cap.
        // `U+1F600` (😀) encodes as 4 bytes in UTF-8.
        let v: String = "\u{1f600}".repeat(200);
        assert_eq!(v.chars().count(), 200);
        assert_eq!(v.len(), 800);
        assert!(validate_route_param("repo_key", &v).is_err());
    }

    // -- BoundedPath<T> extractor --------------------------------------------

    use axum::body::Body as AxumBody;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn echo_single(BoundedPath(value): BoundedPath<String>) -> String {
        value
    }

    async fn echo_tuple_two(BoundedPath((a, b)): BoundedPath<(String, String)>) -> String {
        format!("{a}|{b}")
    }

    async fn echo_tuple_three(
        BoundedPath((a, b, c)): BoundedPath<(String, String, String)>,
    ) -> String {
        format!("{a}|{b}|{c}")
    }

    async fn echo_tuple_four(
        BoundedPath((a, b, c, d)): BoundedPath<(String, String, String, String)>,
    ) -> String {
        format!("{a}|{b}|{c}|{d}")
    }

    fn router() -> Router {
        Router::new()
            .route("/one/{repo_key}", get(echo_single))
            .route("/two/{repo_key}/{project}", get(echo_tuple_two))
            .route(
                "/three/{repo_key}/{project}/{filename}",
                get(echo_tuple_three),
            )
            .route(
                "/four/{repo_key}/{scope}/{name}/{filename}",
                get(echo_tuple_four),
            )
    }

    #[tokio::test]
    async fn bounded_path_accepts_single_segment_under_cap() {
        let res = router()
            .oneshot(
                Request::get("/one/my-repo")
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"my-repo");
    }

    #[tokio::test]
    async fn bounded_path_rejects_single_oversized_with_param_name() {
        let huge = "a".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let res = router()
            .oneshot(
                Request::get(format!("/one/{huge}"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let ct = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(ct, "application/json");

        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        // Parameter name comes from the axum route template (`:repo_key`),
        // matching the pre-refactor `validate_route_param("repo_key", ..)`
        // call site exactly.
        assert_eq!(json["parameter"], "repo_key");
    }

    #[tokio::test]
    async fn bounded_path_accepts_tuple_all_under_cap() {
        let res = router()
            .oneshot(
                Request::get("/three/my-repo/my-proj/my-file.tar.gz")
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"my-repo|my-proj|my-file.tar.gz");
    }

    #[tokio::test]
    async fn bounded_path_rejects_tuple_with_oversized_middle_segment() {
        // Oversized `:project` segment (middle) — proves the extractor
        // walks every capture, not just the first.
        let huge = "p".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let res = router()
            .oneshot(
                Request::get(format!("/three/my-repo/{huge}/file.tar.gz"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "project");
    }

    #[tokio::test]
    async fn bounded_path_rejects_tuple_with_oversized_last_segment() {
        // Oversized `:filename` (tail) — the handler-agnostic equivalent
        // of the PyPI download test that asserted `parameter == "filename"`.
        let huge = "f".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let res = router()
            .oneshot(
                Request::get(format!("/three/my-repo/my-proj/{huge}"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["parameter"], "filename");
    }

    #[tokio::test]
    async fn bounded_path_accepts_at_boundary() {
        // Exactly 512 bytes on every segment — "<= cap" branch. Must
        // not 400. Falls through to the handler (200 + the value).
        let at_cap = "a".repeat(MAX_ROUTE_PARAM_BYTES);
        let res = router()
            .oneshot(
                Request::get(format!("/two/{at_cap}/pkg"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // 200 — request made it through the extractor into the handler.
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bounded_path_four_tuple_rejects_oversized_scope() {
        // 4-arity case — the highest arity in the codebase (npm scoped
        // download). Proves the generic impl handles arities ≥ 4 without
        // needing per-arity code.
        let huge = format!("@{}", "s".repeat(MAX_ROUTE_PARAM_BYTES));
        let res = router()
            .oneshot(
                Request::get(format!("/four/my-repo/{huge}/pkg/file.tgz"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["parameter"], "scope");
    }

    // -- RawPathParams invariant (latent-coverage pin) -----------------------
    //
    // The earlier implementation used a `HashMap<String, String>` pre-pass
    // for the cap check. If that extraction failed, the typed Path<T> pass
    // still ran — so a request where a non-String target happened to
    // deserialize successfully while the HashMap pass did not would skip
    // the cap check entirely. `RawPathParams` closes that window: it yields
    // raw captured segments without any typed deserialization, so the
    // "skip window" doesn't exist.
    //
    // These tests pin the invariant: the cap must fire on routes whose
    // typed-extraction target is NOT `String` (so the hypothetical
    // type-shape-dependent skip branch would be observable if it existed).

    async fn echo_integer(BoundedPath(id): BoundedPath<(u64,)>) -> String {
        id.0.to_string()
    }

    async fn echo_named_struct(BoundedPath(p): BoundedPath<NamedParams>) -> String {
        format!("{}|{}", p.repo_key, p.project)
    }

    #[derive(serde::Deserialize)]
    struct NamedParams {
        repo_key: String,
        project: String,
    }

    fn typed_router() -> Router {
        Router::new()
            .route("/typed/{id}", get(echo_integer))
            .route("/named/{repo_key}/{project}", get(echo_named_struct))
    }

    #[tokio::test]
    async fn bounded_path_cap_fires_when_typed_target_is_integer() {
        // The `:id` captures into a `u64`. Under the old
        // `HashMap<String,String>`-pre-pass design the cap check still
        // ran because HashMap extraction doesn't care about the typed
        // target — but that guarantee was implicit. This test pins it
        // explicitly: even with a non-String typed target, an oversized
        // captured segment must 400 before typed deserialization runs.
        let huge = "9".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let res = typed_router()
            .oneshot(
                Request::get(format!("/typed/{huge}"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "route parameter too long");
        assert_eq!(json["parameter"], "id");
    }

    #[tokio::test]
    async fn bounded_path_cap_fires_on_named_struct_target() {
        // Named-struct target instead of a tuple. `RawPathParams` yields
        // the captures regardless of the typed shape, so the cap still
        // fires.
        let huge = "p".repeat(MAX_ROUTE_PARAM_BYTES + 1);
        let res = typed_router()
            .oneshot(
                Request::get(format!("/named/my-repo/{huge}"))
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(res.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["parameter"], "project");
    }

    #[tokio::test]
    async fn bounded_path_no_captures_route_still_works() {
        // Zero-capture route — `RawPathParams` yields an empty iterator,
        // the cap loop is a no-op, and the handler receives its empty-
        // tuple payload. Regression guard: no panic, no 400.
        async fn empty_handler(BoundedPath(_): BoundedPath<()>) -> &'static str {
            "ok"
        }
        let app = Router::new().route("/root", get(empty_handler));
        let res = app
            .oneshot(Request::get("/root").body(AxumBody::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // -- the publish kill switch ---------------------------------------------
    //
    // Pinned here, at the definition, for the same reason
    // `cargo_publish_body_limit`'s constants are: the composition-level
    // suite (`hort-server/tests/publish_body_limit_composition.rs`)
    // asserts that each publish subtree applies this guard, and these
    // assert what the guard itself promises.

    #[test]
    fn only_publish_carrying_methods_are_held() {
        // The refuse side: the methods a publish arrives on.
        for method in ["POST", "PUT", "PATCH"] {
            assert!(
                method_carries_a_publish(&Method::from_bytes(method.as_bytes()).unwrap()),
                "{method} must be held while the switch is on"
            );
        }
        // The pass side. GET / HEAD / OPTIONS carry no publish, and
        // DELETE is a removal rather than a publish — holding it would
        // strand an OCI upload session a client can no longer finish.
        for method in ["GET", "HEAD", "OPTIONS", "DELETE"] {
            assert!(
                !method_carries_a_publish(&Method::from_bytes(method.as_bytes()).unwrap()),
                "{method} must pass while the switch is on"
            );
        }
    }

    #[tokio::test]
    async fn the_refusal_is_503_json_and_quotes_no_deadline() {
        let resp = publish_disabled_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "application/json"
        );
        // The hold has no deadline to quote; a fabricated one would be
        // a lie a well-behaved client then acts on.
        assert!(resp
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());

        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "publishing is disabled on this server");
        // The body carries what the missing header cannot.
        assert!(json["detail"].as_str().unwrap().contains("Retry-After"));
    }

    /// Distinct refusal body so the test can tell "the guard ran" from
    /// "the handler answered", and so the per-subtree
    /// [`PublishRefusal`] seam is exercised rather than assumed.
    fn marker_refusal() -> Response {
        (StatusCode::SERVICE_UNAVAILABLE, "held").into_response()
    }

    /// Inner handler the guard either reaches or holds. Shared by every
    /// router below so "the inner service ran" is one observation
    /// rather than one per test.
    async fn reached() -> &'static str {
        "reached"
    }

    fn guarded_router(limit: usize) -> Router {
        let routes = Router::new().route(
            "/pkg",
            get(reached).head(reached).post(reached).delete(reached),
        );
        refuse_publishes_when_disabled(routes, limit, marker_refusal)
    }

    async fn guarded_status_and_body(
        limit: usize,
        request: Request<AxumBody>,
    ) -> (StatusCode, String) {
        let resp = guarded_router(limit).oneshot(request).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 1024).await.unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn a_zero_limit_holds_a_publish_with_the_subtrees_own_refusal() {
        let (status, body) =
            guarded_status_and_body(0, Request::post("/pkg").body(AxumBody::empty()).unwrap())
                .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        // The guard served the refusal this subtree supplied — the seam
        // `hort-http-oci` uses to answer in the OCI error envelope.
        assert_eq!(body, "held");
    }

    #[tokio::test]
    async fn a_zero_limit_leaves_reads_and_deletes_alone() {
        for request in [
            Request::get("/pkg").body(AxumBody::empty()).unwrap(),
            Request::head("/pkg").body(AxumBody::empty()).unwrap(),
            Request::delete("/pkg").body(AxumBody::empty()).unwrap(),
        ] {
            let method = request.method().clone();
            let (status, _) = guarded_status_and_body(0, request).await;
            assert_eq!(status, StatusCode::OK, "{method} was held");
        }
    }

    #[tokio::test]
    async fn a_non_zero_limit_attaches_no_guard_at_all() {
        // Not merely "the publish is admitted": the `limit != 0` branch
        // returns the router untouched, so an over-size body keeps
        // reaching whatever `DefaultBodyLimit` the subtree configured
        // and its own `413`.
        let (status, body) =
            guarded_status_and_body(1, Request::post("/pkg").body(AxumBody::empty()).unwrap())
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "reached");
    }

    #[tokio::test]
    async fn a_mutating_method_no_route_registers_is_still_held() {
        // Measured, not assumed: `route_layer` wraps the matched route's
        // whole `MethodRouter`, the `405`-for-an-unregistered-method
        // fallback included, so the guard sees a `POST` at a `GET`-only
        // path and holds it. Worth pinning because it is the opposite of
        // the intuition that a layer runs only for registered methods,
        // and because it is the fail-closed direction: while the switch
        // is on, a mutating method that matches a path cannot reach a
        // handler by being absent from the method router.
        let routes = Router::new().route("/read-only", get(reached));
        let resp = refuse_publishes_when_disabled(routes, 0, marker_refusal)
            .oneshot(Request::post("/read-only").body(AxumBody::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn an_unmatched_path_is_not_held() {
        // `route_layer`, not `layer`: the guard must not answer for a
        // path the subtree does not serve, or a typo'd URL would report
        // a publish hold on a route that does not exist.
        let resp = guarded_router(0)
            .oneshot(Request::post("/nope").body(AxumBody::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
