use std::sync::Arc;

use hort_config::ExtraTrustAnchors;
use object_store::aws::AmazonS3Builder;
use object_store::ClientOptions;
use object_store::ObjectStore;

use crate::extra_ca::apply_to_object_store_options;
use crate::metrics::values;
use crate::object_store_backend::ObjectStoreStorage;

/// Server-side-encryption mode for S3 puts.
///
/// The variants map to the three operator-observable behaviours:
///
/// - [`SseMode::BucketDefault`] — emit nothing on the request. Whatever
///   default the bucket is configured for applies. AWS S3 has applied
///   SSE-S3 unconditionally since 2023, so this is the right default for
///   AWS. Non-AWS S3-compatibles (MinIO, Garage, Ceph RGW) expose the
///   knob per-bucket; the [`build_s3_object_store`] WARN heuristic
///   surfaces the case where the operator has not configured one.
/// - [`SseMode::Sse256`] — request SSE-S3 (`AES256`) on every put. The
///   bucket key (object_store-managed encryption key, AWS-side) handles
///   the actual ciphering.
/// - [`SseMode::SseKms { key_arn }`] — request SSE-KMS on every put,
///   keyed by the supplied KMS key ARN. The KMS key MUST grant the S3
///   service permission to use it (`kms:Encrypt`, `kms:Decrypt`,
///   `kms:GenerateDataKey*`); misconfiguration surfaces as a 5xx on the
///   first put.
///
/// ## Divergence from the original spec
///
/// The original backlog said the translation would be
/// `AmazonS3Builder::with_attribute(Attribute::ServerSideEncryption, …)`.
/// That API does not exist in `object_store` 0.13.2 — `Attribute` is the
/// per-object metadata enum (`ContentType`, `Metadata`, …). The actual
/// API is `with_sse_kms_encryption(kms_key_id)` (for SSE-KMS) and
/// `with_config(AmazonS3ConfigKey::Encryption(
/// S3EncryptionConfigKey::ServerSideEncryption), "AES256")` (for
/// SSE-S3). [`apply_sse`] performs that translation; tests assert the
/// outcome via `AmazonS3Builder::get_config_value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SseMode {
    /// Honour whatever encryption default the bucket itself has.
    BucketDefault,
    /// SSE-S3: AWS-managed keys, AES256.
    Sse256,
    /// SSE-KMS: customer-managed KMS key.
    SseKms {
        /// Full KMS key ARN, e.g.
        /// `arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678`.
        key_arn: String,
    },
}

/// Configure SSE on the S3 builder per the supplied [`SseMode`].
///
/// `None` and `Some(BucketDefault)` are equivalent at the builder layer:
/// neither writes any encryption config, leaving the request to fall back
/// to the bucket's default. `Sse256` writes `AES256` to the
/// `aws_server_side_encryption` config slot. `SseKms` calls
/// `with_sse_kms_encryption`, which sets BOTH the encryption type to
/// `aws:kms` AND the KMS key id atomically.
fn apply_sse(builder: AmazonS3Builder, sse_mode: Option<&SseMode>) -> AmazonS3Builder {
    match sse_mode {
        None | Some(SseMode::BucketDefault) => builder,
        Some(SseMode::Sse256) => {
            // `S3EncryptionConfigKey::ServerSideEncryption` is not
            // re-exported from `object_store::aws` (only
            // `AmazonS3Builder` and `AmazonS3ConfigKey` are). We
            // therefore set the slot via `with_config` parsed from
            // the documented string key name; the parser at
            // `aws/builder.rs:531` accepts both
            // `aws_server_side_encryption` and
            // `server_side_encryption`. The value `"AES256"` is the
            // wire value the AWS S3 API expects in the
            // `x-amz-server-side-encryption` header for SSE-S3.
            let key = "aws_server_side_encryption"
                .parse()
                .expect("aws_server_side_encryption is a documented AmazonS3ConfigKey alias");
            builder.with_config(key, "AES256")
        }
        Some(SseMode::SseKms { key_arn }) => builder.with_sse_kms_encryption(key_arn.clone()),
    }
}

/// Strip scheme, userinfo, path, and query from an endpoint URL,
/// returning just `host:port` for safe inclusion in tracing output.
///
/// Does NOT pull in the `url` crate — we only need a coarse strip and
/// the input shape is bounded (operator-supplied S3 endpoint). The
/// userinfo strip is defensive (operators should never put credentials
/// in the endpoint URL).
fn endpoint_host_port(endpoint: &str) -> String {
    // Strip scheme://
    let after_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    // Strip userinfo (anything before @ in the authority)
    let after_userinfo = after_scheme
        .split_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    // Take authority — everything before the first /, ?, or #
    let authority_end = after_userinfo
        .find(['/', '?', '#'])
        .unwrap_or(after_userinfo.len());
    after_userinfo[..authority_end].to_string()
}

/// `true` when `endpoint`'s host portion is an AWS S3 endpoint.
/// The non-AWS-and-no-SSE WARN fired for any operator-supplied
/// endpoint, including AWS endpoints typed explicitly
/// (`https://s3.us-east-1.amazonaws.com`, `https://s3-fips.us-east-2.amazonaws.com`,
/// `https://my-bucket.s3.amazonaws.com`, etc.). The original heuristic
/// "endpoint = None ⇒ AWS, Some ⇒ non-AWS" is correct in spirit (AWS S3
/// has applied SSE-S3 unconditionally since 2023) but produces a
/// false-positive WARN whenever an operator records the AWS endpoint
/// for clarity rather than leaving it unset.
///
/// Match suffixes (lowercased host with port stripped):
/// - `.amazonaws.com` — global AWS commercial, GovCloud,
///   virtual-hosted-style buckets, all regions
/// - `.amazonaws.com.cn` — AWS China (`cn-north-1`, `cn-northwest-1`)
///
/// These two suffixes cover every documented AWS S3 endpoint shape.
/// FIPS / dualstack / regional / virtual-hosted variants all roll up
/// under one of these suffixes. The exotic intelligence-community
/// regions (`*.c2s.ic.gov`, `*.sc2s.sgov.gov`) are deliberately NOT
/// suppressed — operators using them are sophisticated enough to set
/// `sseMode` explicitly, and the false-positive WARN is cheap insurance
/// against an unfamiliar deployment dropping the SSE configuration.
fn looks_like_aws_s3_endpoint(host_port: &str) -> bool {
    let host = host_port
        .rsplit_once(':')
        .map_or(host_port, |(host, _port)| host)
        .to_ascii_lowercase();
    host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn")
}

/// Options bundle for constructing an S3-compatible object store.
///
/// Replaces the previous 7-positional-argument signatures on
/// `build_s3_object_store` and `build_s3_storage`. Adding
/// `extra_trust_anchors` would have pushed both functions to 8 positional
/// params — well past clippy's default `too_many_arguments` threshold of 7.
/// This struct pays the refactor down once rather than continuing to grow
/// the suppression surface.
///
/// ## Custom `Debug`
///
/// The `Debug` implementation emits `extra_trust_anchors_count` (the number
/// of DER-encoded certificates) rather than the raw cert bytes (which are
/// multi-kilobyte and structurally unreadable in log output). The
/// `secret_key` field is redacted as `"<redacted>"` to prevent accidental
/// credential exposure in log pipelines.
#[derive(Clone)]
pub struct S3StorageOpts<'a> {
    /// S3 bucket name.
    pub bucket: &'a str,
    /// Optional endpoint URL (e.g. `http://minio:9000` for MinIO/Garage).
    /// `None` routes to AWS S3 using the default endpoint.
    pub endpoint: Option<&'a str>,
    /// Use path-style request routing (`/bucket/key`) rather than
    /// virtual-hosted style (`bucket.s3.amazonaws.com/key`). Required for
    /// MinIO, Garage, and other S3-compatible stores.
    pub force_path_style: bool,
    /// Allow plain HTTP endpoints. The config layer rejects mismatched
    /// `(scheme, flag)` pairs before this builder is called, so
    /// `allow_http = true` implies `endpoint` starts with `http://`.
    pub allow_http: bool,
    /// AWS region (e.g. `us-east-1`). Required by the S3 protocol even
    /// for non-AWS stores; set to `us-east-1` if your store ignores it.
    pub region: &'a str,
    /// AWS access key ID.
    pub access_key: &'a str,
    /// AWS secret access key. Redacted in the `Debug` output.
    pub secret_key: &'a str,
    /// Process-wide extra CA trust bundle (ADR 0010). When `Some`, the
    /// certificates are added to the underlying `reqwest` client via
    /// [`object_store::ClientOptions::with_root_certificate`] so the S3
    /// adapter trusts the operator-supplied internal CA in addition to the
    /// OS/system root store.
    pub extra_trust_anchors: Option<&'a ExtraTrustAnchors>,
    /// Server-side-encryption mode. `None` preserves the prior behaviour:
    /// no encryption opinion is sent in the request, and whatever
    /// bucket-default applies takes effect.
    /// `Some(...)` translates into a builder-level encryption config —
    /// see [`SseMode`] for the variant semantics. When `endpoint` is
    /// `Some` (operator-supplied, i.e. non-AWS S3-compatible) AND
    /// `sse_mode` is `None`, [`build_s3_object_store`] emits a startup
    /// WARN naming the endpoint host:port: AWS S3 has applied SSE-S3
    /// unconditionally since 2023 but S3-compatibles vary, so the
    /// silent-cleartext-at-rest case is worth surfacing.
    pub sse_mode: Option<SseMode>,
}

impl std::fmt::Debug for S3StorageOpts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3StorageOpts")
            .field("bucket", &self.bucket)
            .field("endpoint", &self.endpoint)
            .field("force_path_style", &self.force_path_style)
            .field("allow_http", &self.allow_http)
            .field("region", &self.region)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field(
                "extra_trust_anchors_count",
                &self
                    .extra_trust_anchors
                    .map_or(0, ExtraTrustAnchors::cert_count),
            )
            // `SseMode::SseKms { key_arn }` carries the operator-supplied
            // KMS ARN, which is not a secret (it's an identifier, not a
            // credential), but redacting via the dedicated Debug field
            // keeps the redaction policy of this struct consistent with
            // the credential fields above.
            .field("sse_mode", &self.sse_mode)
            .finish()
    }
}

/// Decide whether the "non-AWS endpoint without explicit SSE" startup
/// WARN should fire, and if so the host:port to surface in it.
///
/// Pure (no `tracing`) so the decision is unit-testable without touching
/// the process-global tracing callsite-interest cache. The previous
/// capture-subscriber test for this WARN was inherently flaky under
/// parallel `cargo test` / `cargo llvm-cov`: the `build_succeeds_*` tests
/// also reach this callsite under the default `NoSubscriber`, which could
/// poison the global interest cache to `Interest::never()` and silently
/// drop the event before any capturing layer saw it. Testing this
/// function removes that entire flake class.
///
/// Returns `Some(host_port)` when `endpoint` is set, `sse_mode` is `None`,
/// and the endpoint is not a recognised AWS S3 endpoint; `None` otherwise.
/// The returned value is already reduced to host:port (scheme, path, and
/// any userinfo credentials stripped by [`endpoint_host_port`]) so it is
/// safe to log.
fn missing_sse_warning_host_port(
    endpoint: Option<&str>,
    sse_mode: Option<&SseMode>,
) -> Option<String> {
    let (Some(ep), None) = (endpoint, sse_mode) else {
        return None;
    };
    let host_port = endpoint_host_port(ep);
    if looks_like_aws_s3_endpoint(&host_port) {
        None
    } else {
        Some(host_port)
    }
}

/// Build an S3-compatible object store (AWS S3, MinIO, Garage, etc.).
///
/// For MinIO/Garage, set `force_path_style = true` and provide the endpoint
/// URL. For AWS S3 with virtual-hosted style, set `force_path_style = false`
/// and leave `endpoint` as `None`.
///
/// `allow_http = true` opts the underlying `AmazonS3Builder` into plain
/// HTTP endpoints (the rust `object_store` crate refuses HTTP by default).
/// The config layer rejects mismatched (scheme, flag) pairs before this
/// builder is called, so `allow_http = true` here implies the endpoint
/// is `Some(http://…)`.
///
/// `extra_trust_anchors` is applied to the underlying `reqwest` client via
/// [`object_store::ClientOptions::with_root_certificate`] (ADR 0010).
///
/// # Errors
///
/// Returns `object_store::Error` if:
/// - Any certificate in `extra_trust_anchors` is rejected by `reqwest`
///   (e.g. structurally invalid DER).
/// - The builder configuration is otherwise invalid (e.g. missing bucket
///   name).
pub fn build_s3_object_store(
    opts: &S3StorageOpts<'_>,
) -> Result<Arc<dyn ObjectStore>, object_store::Error> {
    // `ClientOptions` carries `allow_http` for the underlying reqwest
    // client; `AmazonS3Builder::with_allow_http` is a separate builder-
    // layer flag. When `with_client_options(custom)` is called, the
    // builder uses the supplied `ClientOptions` for the reqwest layer
    // wholesale — so `AmazonS3Builder::with_allow_http(true)` becomes a
    // no-op at the reqwest layer, and `.build()` fails synchronously
    // against any `http://` endpoint regardless of the builder flag.
    //
    // Apply `allow_http` to `ClientOptions` BEFORE
    // `apply_to_object_store_options` layers the extra-CA anchors on,
    // so both flags propagate into the reqwest client. Commit ad26c26
    // introduced the regression by adding the `with_client_options(client_opts)`
    // call without threading `allow_http` through the new `ClientOptions`
    // instance.
    let mut base_opts = ClientOptions::new();
    if opts.allow_http {
        base_opts = base_opts.with_allow_http(true);
    }
    let client_opts = apply_to_object_store_options(base_opts, opts.extra_trust_anchors)?;

    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(opts.bucket)
        .with_region(opts.region)
        .with_access_key_id(opts.access_key)
        .with_secret_access_key(opts.secret_key)
        .with_virtual_hosted_style_request(!opts.force_path_style)
        .with_allow_http(opts.allow_http)
        .with_client_options(client_opts);

    if let Some(ep) = opts.endpoint {
        builder = builder.with_endpoint(ep);
    }

    // Translate the operator's chosen SSE mode into the corresponding
    // `AmazonS3Builder` configuration.
    builder = apply_sse(builder, opts.sse_mode.as_ref());

    // WARN when the operator points the adapter at a non-AWS endpoint AND
    // has not opted in to a specific SSE mode. AWS S3 has applied SSE-S3
    // unconditionally since 2023 so the heuristic deliberately skips that
    // case (`endpoint = None` ⇒ AWS, OR `endpoint` matches an AWS host
    // suffix per `looks_like_aws_s3_endpoint`). Non-AWS S3-compatibles
    // vary; the operator must configure a bucket-level default OR opt
    // in here. The suffix-aware skip closes the false-positive WARN for
    // operators who type the AWS endpoint explicitly
    // (`s3.<region>.amazonaws.com` etc.).
    //
    // The endpoint is reduced to host:port before logging — defensive
    // even though the operator should never put credentials in the
    // URL — so a misconfigured endpoint can't echo secrets into log
    // pipelines.
    if let Some(host_port) = missing_sse_warning_host_port(opts.endpoint, opts.sse_mode.as_ref()) {
        tracing::warn!(
            endpoint_host_port = %host_port,
            "S3 endpoint is non-AWS and sse_mode is None — bucket-default SSE may not be configured"
        );
    }

    Ok(Arc::new(builder.build()?))
}

/// Build an `ObjectStoreStorage` backed by an S3-compatible store, tagged
/// with the canonical `BACKEND_S3` label so every metric emitted by the
/// returned adapter carries `backend="s3"`.
///
/// # Errors
///
/// Returns `object_store::Error` if the underlying builder configuration is
/// invalid (e.g. missing bucket name or a rejected CA certificate).
pub fn build_s3_storage(
    opts: &S3StorageOpts<'_>,
) -> Result<ObjectStoreStorage, object_store::Error> {
    let store = build_s3_object_store(opts)?;
    Ok(ObjectStoreStorage::new(store, values::BACKEND_S3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::aws::AmazonS3ConfigKey;
    use object_store::ObjectStoreExt;

    /// The `S3EncryptionConfigKey` enum that `AmazonS3ConfigKey::Encryption`
    /// wraps is not re-exported from `object_store::aws`. The public
    /// FromStr impl on `AmazonS3ConfigKey` accepts the documented string
    /// keys (`aws_server_side_encryption`, `aws_sse_kms_key_id`, …) and
    /// is the only public way to construct these variants. The keys
    /// themselves are stable per the `S3EncryptionConfigKey` doc
    /// comments.
    fn server_side_encryption_key() -> AmazonS3ConfigKey {
        "aws_server_side_encryption"
            .parse()
            .expect("aws_server_side_encryption is a documented AmazonS3ConfigKey alias")
    }

    fn kms_key_id_key() -> AmazonS3ConfigKey {
        "aws_sse_kms_key_id"
            .parse()
            .expect("aws_sse_kms_key_id is a documented AmazonS3ConfigKey alias")
    }

    fn opts<'a>(endpoint: &'a str, allow_http: bool) -> S3StorageOpts<'a> {
        S3StorageOpts {
            bucket: "test-bucket",
            endpoint: Some(endpoint),
            force_path_style: true,
            allow_http,
            region: "us-east-1",
            access_key: "test-access-key",
            secret_key: "test-secret-key",
            extra_trust_anchors: None,
            sse_mode: None,
        }
    }

    #[test]
    fn build_succeeds_for_http_endpoint_when_allow_http_is_true() {
        // Smoke test: the `(scheme, flag)` contract is enforced by reqwest
        // at request-construction time, not at `AmazonS3Builder::build()`
        // time, so this test alone does not lock the regression. The
        // `request_against_http_endpoint_*` tokio test below pins the
        // reqwest-layer behaviour directly.
        let result = build_s3_object_store(&opts("http://garage:3900", true));
        assert!(
            result.is_ok(),
            "build_s3_object_store must accept http:// endpoint when allow_http=true; got {:?}",
            result.err(),
        );
    }

    #[test]
    fn build_succeeds_for_https_endpoint_when_allow_http_is_false() {
        // Happy-path regression: the default-secure case must keep working.
        let result = build_s3_object_store(&opts("https://s3.example.com", false));
        assert!(
            result.is_ok(),
            "build_s3_object_store must accept https:// endpoint when allow_http=false; got {:?}",
            result.err(),
        );
    }

    /// Regression guard for commit ad26c26, where the
    /// `with_client_options(custom)` override silently dropped
    /// `AmazonS3Builder::with_allow_http(true)` at the reqwest layer.
    ///
    /// Pre-fix, `ClientOptions::new()` defaults to `allow_http = false`,
    /// which configures the reqwest client with `https_only(true)`. Any
    /// request to an `http://` URL is rejected at request-construction
    /// inside reqwest with a `URL scheme is not allowed` error — BEFORE
    /// any DNS resolution or connect attempt.
    ///
    /// Post-fix, `allow_http` is threaded into `ClientOptions` before the
    /// extra-CA anchors are layered on, so reqwest is built with
    /// `https_only(false)` and accepts http URLs at request-construction.
    /// The request then fails at the connect layer with a
    /// `Connection refused` against the closed port.
    ///
    /// The test pins the post-fix behaviour by asserting the error
    /// references the closed-port socket address (proving reqwest got
    /// past scheme validation and attempted a connect) and is NOT a
    /// scheme-rejection error.
    #[tokio::test]
    async fn request_against_http_endpoint_reaches_reqwest_layer_when_allow_http_is_true() {
        // Port 1 is reserved per IANA and never actually bound, so the
        // connect attempt fails with a deterministic "Connection refused"
        // (Linux) / similar errno on every supported platform. Using a
        // bound listener would race; using a closed port is reliable.
        let store = build_s3_object_store(&opts("http://127.0.0.1:1", true))
            .expect("build_s3_object_store must succeed with allow_http=true and http:// endpoint");

        let err = store
            .head(&object_store::path::Path::from("nonexistent-key"))
            .await
            .expect_err("head against closed port must fail");

        // The discriminator between the two states is the reqwest error
        // kind. Pre-fix object_store 0.13 surfaces
        // `reqwest::Error { kind: Builder, source: BadScheme }` because
        // reqwest's `https_only(true)` rejects the http URL inside
        // `Client::request(...)` BEFORE any DNS resolution. Post-fix the
        // error is `kind: Connect, source: ConnectError("tcp connect
        // error", ..., ConnectionRefused)` against the closed port.
        let msg = format!("{err:?}");
        assert!(
            !msg.contains("BadScheme") && !msg.contains("kind: Builder"),
            "error must not be a reqwest scheme rejection — that means \
             allow_http=true did not propagate to ClientOptions and \
             reqwest was built with https_only(true). Got: {msg}",
        );
        assert!(
            msg.contains("ConnectionRefused") || msg.contains("kind: Connect"),
            "error must show reqwest got past scheme validation and \
             attempted a TCP connect against the closed port. Got: {msg}",
        );
    }

    // -- SSE / SSE-KMS -----------------------------------------------------
    //
    // Architectural note (DIVERGENCE from the original spec):
    // The original acceptance text says
    //   "AmazonS3Builder::with_attribute(Attribute::ServerSideEncryption, …)"
    // but `Attribute` in object_store 0.13.2 is the *per-object* metadata
    // enum (ContentType, Metadata, …) and has no `ServerSideEncryption`
    // variant — `with_attribute` is not a builder method either. The
    // actual API is `AmazonS3Builder::with_sse_kms_encryption(kms_key_id)`
    // for SSE-KMS and `with_config(AmazonS3ConfigKey::Encryption(
    // S3EncryptionConfigKey::ServerSideEncryption), "AES256")` for
    // SSE-S3. Tests assert via `get_config_value` which reads back from
    // the same internal field, so a mis-translation in `apply_sse` is
    // observable without making any HTTP request.

    /// `BucketDefault` (and `None`) MUST leave the encryption
    /// configuration untouched on the builder. The bucket's own default
    /// encryption (AWS S3 has applied SSE-S3 unconditionally since
    /// 2023) takes effect for AWS targets; for non-AWS S3-compatibles
    /// the operator is responsible for configuring bucket-level
    /// defaults out-of-band, which the WARN heuristic surfaces.
    #[test]
    fn apply_sse_bucket_default_leaves_encryption_unset() {
        let builder = AmazonS3Builder::new();
        let configured = apply_sse(builder, Some(&SseMode::BucketDefault));

        assert_eq!(
            configured.get_config_value(&server_side_encryption_key()),
            None,
            "BucketDefault must NOT set ServerSideEncryption on the builder",
        );
        assert_eq!(
            configured.get_config_value(&kms_key_id_key()),
            None,
            "BucketDefault must NOT set a KMS key id",
        );
    }

    /// `Sse256` MUST set the `aws_server_side_encryption` config slot to
    /// `"AES256"`. This is the wire value the AWS S3 API expects in the
    /// `x-amz-server-side-encryption` header for SSE-S3.
    #[test]
    fn apply_sse_sse256_sets_aes256_config_value() {
        let builder = AmazonS3Builder::new();
        let configured = apply_sse(builder, Some(&SseMode::Sse256));

        assert_eq!(
            configured
                .get_config_value(&server_side_encryption_key())
                .as_deref(),
            Some("AES256"),
            "Sse256 must configure ServerSideEncryption=\"AES256\"",
        );
    }

    /// `SseKms { key_arn }` MUST set BOTH the encryption type to
    /// `"aws:kms"` AND the KMS key id to the supplied ARN. The
    /// `with_sse_kms_encryption` builder method on `AmazonS3Builder`
    /// performs both writes atomically, but the test asserts both
    /// observables to lock the contract: a future refactor that
    /// dropped the key id (because "the bucket has a default key")
    /// must fail this test.
    #[test]
    fn apply_sse_sse_kms_sets_both_type_and_key_arn() {
        let arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh-5678";
        let builder = AmazonS3Builder::new();
        let configured = apply_sse(
            builder,
            Some(&SseMode::SseKms {
                key_arn: arn.to_string(),
            }),
        );

        assert_eq!(
            configured
                .get_config_value(&server_side_encryption_key())
                .as_deref(),
            Some("aws:kms"),
            "SseKms must configure ServerSideEncryption=\"aws:kms\"",
        );
        assert_eq!(
            configured.get_config_value(&kms_key_id_key()).as_deref(),
            Some(arn),
            "SseKms must configure the KMS key ARN",
        );
    }

    /// When the operator points the S3 adapter at a non-AWS endpoint AND has
    /// not opted in to a specific SSE mode, startup MUST emit a WARN. The
    /// heuristic catches the silent-data-at-rest-cleartext case on
    /// S3-compatibles where bucket-default encryption is not mandatory
    /// (unlike AWS S3, which has applied SSE-S3 unconditionally since 2023).
    ///
    /// The emission itself is a one-line `tracing::warn!` wrapper around
    /// the pure [`missing_sse_warning_host_port`]; the decision logic is
    /// tested here directly. A prior version captured the emitted event
    /// via a thread-local `tracing_subscriber` layer, but that test was
    /// inherently flaky: the same `warn!` callsite is reached by the
    /// `build_succeeds_*` tests under the default `NoSubscriber`, and
    /// under parallel `cargo test` / `cargo llvm-cov` the process-global
    /// tracing callsite-interest cache could resolve the callsite to
    /// `Interest::never()` before the capturing layer saw the event
    /// (`captured records: []`). Testing the pure decision removes that
    /// global-cache race entirely.
    #[test]
    fn missing_sse_warning_fires_for_non_aws_endpoint_without_sse() {
        let host_port = missing_sse_warning_host_port(Some("https://minio.internal:9000"), None);
        assert_eq!(
            host_port.as_deref(),
            Some("minio.internal:9000"),
            "non-AWS endpoint + sse_mode None must surface the host:port for the WARN",
        );
    }

    #[test]
    fn missing_sse_warning_strips_endpoint_userinfo_credentials() {
        // Even if an operator embeds credentials in the endpoint URL, the
        // WARN value must never carry them — the heuristic logs host:port
        // only (mirrors `endpoint_host_port_strips_userinfo_credentials`).
        let host_port = missing_sse_warning_host_port(
            Some("https://access:secret@minio.internal:9000/bucket"),
            None,
        )
        .expect("non-AWS endpoint + sse_mode None must warn");
        assert_eq!(host_port, "minio.internal:9000");
        assert!(
            !host_port.contains("access") && !host_port.contains("secret"),
            "WARN host:port must NEVER carry endpoint userinfo credentials; got: {host_port}",
        );
    }

    #[test]
    fn missing_sse_warning_silent_when_sse_mode_explicit() {
        assert_eq!(
            missing_sse_warning_host_port(
                Some("https://minio.internal:9000"),
                Some(&SseMode::Sse256),
            ),
            None,
            "an explicit SseMode must suppress the missing-SSE WARN",
        );
    }

    #[test]
    fn missing_sse_warning_silent_for_aws_endpoint() {
        assert_eq!(
            missing_sse_warning_host_port(Some("https://s3.us-east-1.amazonaws.com"), None),
            None,
            "AWS endpoints apply default SSE unconditionally; no WARN",
        );
    }

    #[test]
    fn missing_sse_warning_silent_when_no_custom_endpoint() {
        assert_eq!(
            missing_sse_warning_host_port(None, None),
            None,
            "the default AWS endpoint (no custom endpoint) must not WARN",
        );
    }

    // -- host:port redaction unit tests ---------------------------------

    #[test]
    fn endpoint_host_port_strips_scheme_and_path() {
        assert_eq!(
            endpoint_host_port("https://minio.internal:9000"),
            "minio.internal:9000",
        );
        assert_eq!(
            endpoint_host_port("http://garage:3900/bucket"),
            "garage:3900",
        );
    }

    #[test]
    fn endpoint_host_port_strips_userinfo_credentials() {
        // Defensive: even though the operator should never put
        // credentials in the endpoint URL, if they do the WARN must
        // still strip them rather than echoing them into logs.
        assert_eq!(
            endpoint_host_port("https://user:pass@minio.internal:9000/bucket"),
            "minio.internal:9000",
        );
    }

    // -----------------------------------------------------------------
    // looks_like_aws_s3_endpoint
    // -----------------------------------------------------------------

    #[test]
    fn aws_endpoint_global_path_style_is_recognised() {
        assert!(looks_like_aws_s3_endpoint("s3.amazonaws.com"));
        assert!(looks_like_aws_s3_endpoint("s3.us-east-1.amazonaws.com"));
        assert!(looks_like_aws_s3_endpoint("s3.eu-west-3.amazonaws.com"));
    }

    #[test]
    fn aws_endpoint_virtual_hosted_style_is_recognised() {
        assert!(looks_like_aws_s3_endpoint(
            "my-bucket.s3.us-east-1.amazonaws.com"
        ));
        assert!(looks_like_aws_s3_endpoint("my-bucket.s3.amazonaws.com"));
    }

    #[test]
    fn aws_endpoint_dualstack_and_fips_are_recognised() {
        assert!(looks_like_aws_s3_endpoint(
            "s3.dualstack.us-west-2.amazonaws.com"
        ));
        assert!(looks_like_aws_s3_endpoint(
            "s3-fips.us-east-2.amazonaws.com"
        ));
    }

    #[test]
    fn aws_endpoint_china_region_is_recognised() {
        assert!(looks_like_aws_s3_endpoint("s3.cn-north-1.amazonaws.com.cn"));
        assert!(looks_like_aws_s3_endpoint(
            "s3.cn-northwest-1.amazonaws.com.cn"
        ));
    }

    #[test]
    fn aws_endpoint_with_explicit_port_is_recognised() {
        assert!(looks_like_aws_s3_endpoint("s3.us-east-1.amazonaws.com:443"));
    }

    #[test]
    fn aws_endpoint_case_insensitive() {
        // Defensive: hostnames are case-insensitive per RFC 1035 §2.3.3.
        assert!(looks_like_aws_s3_endpoint("S3.US-EAST-1.AMAZONAWS.COM"));
    }

    #[test]
    fn non_aws_s3_compatible_endpoints_are_not_recognised() {
        assert!(!looks_like_aws_s3_endpoint("minio.internal:9000"));
        assert!(!looks_like_aws_s3_endpoint("garage:3900"));
        assert!(!looks_like_aws_s3_endpoint("storage.googleapis.com"));
        assert!(!looks_like_aws_s3_endpoint(
            "bucket.r2.cloudflarestorage.com"
        ));
        // Defence-in-depth: a homoglyph / suffix-spoof shape MUST NOT
        // pass — the helper's `ends_with` already prevents this since
        // a substring match would fail without the leading dot.
        assert!(!looks_like_aws_s3_endpoint("notamazonaws.com"));
        assert!(!looks_like_aws_s3_endpoint(
            "amazonaws.com.attacker.example"
        ));
    }
}
