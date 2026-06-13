//! Inbound-adapter request-shape limits.
//!
//! Centralises the body-size, multipart-field, and route-parameter caps
//! applied by every format handler. Consolidating the constants here
//! keeps the ceilings in one place instead of scattered per-handler
//! literals. The rationale behind each number is documented on the
//! constant itself.

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{FromRequestParts, Path, RawPathParams};
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;

/// Default per-publish body-size ceiling applied to formats that don't
/// declare their own override (PyPI and npm today). 300 MiB — generous
/// enough for every legitimate tarball shape across the formats that
/// share this default, tight enough to reject runaway uploads.
///
/// Overridable at runtime via the `HORT_PUBLISH_BODY_MAX_SIZE`
/// environment variable, parsed in `hort-server::config::Config`. The
/// parsed override (or the default) is threaded through `AppContext`
/// and consumed by each format's route builder — no handler reads the
/// env var directly.
pub const DEFAULT_PUBLISH_BODY_LIMIT: usize = 300 * 1024 * 1024;

/// Fixed per-publish body-size ceiling for Cargo. Cargo crates are
/// meaningfully smaller than Python wheels or npm tarballs in practice,
/// so a tighter 200 MiB ceiling is appropriate. Not driven by
/// `HORT_PUBLISH_BODY_MAX_SIZE` — that override ties to the shared
/// 300 MiB default and changing cargo's ceiling silently alongside
/// npm/PyPI would surprise operators who tuned the shared variable for
/// Python wheels. A future item can introduce a cargo-specific override
/// if operational data calls for one.
pub const CARGO_PUBLISH_BODY_LIMIT: usize = 200 * 1024 * 1024;

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

#[async_trait]
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
            .route("/one/:repo_key", get(echo_single))
            .route("/two/:repo_key/:project", get(echo_tuple_two))
            .route("/three/:repo_key/:project/:filename", get(echo_tuple_three))
            .route(
                "/four/:repo_key/:scope/:name/:filename",
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
            .route("/typed/:id", get(echo_integer))
            .route("/named/:repo_key/:project", get(echo_named_struct))
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
}
