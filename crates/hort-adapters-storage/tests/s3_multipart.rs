//! #53 reproduction: large-blob S3-multipart pull-through hang against a
//! real Garage (S3-compatible) container.
//!
//! Stands up `dxflrs/garage:v2.2.0` (prod's version) via `testcontainers`, bootstraps a
//! single-node cluster (layout assign/apply, bucket, API key) via the
//! `garage` CLI inside the container, then exercises
//! `ObjectStoreStorage::put` against it — the exact code path the
//! pull-through ingest uses (`crates/hort-adapters-storage/src/object_store_backend.rs`).
//!
//! **Gating.** All tests early-return when `HORT_TEST_S3=1` is unset so
//! dev environments without Docker keep the suite green — same gating
//! discipline as `hort-notifier-nats`'s `HORT_TEST_NATS` and
//! `hort-adapters-postgres`'s `DATABASE_URL` tiers.
//!
//! ```bash
//! HORT_TEST_S3=1 RUST_LOG=object_store=debug,hort_adapters_storage=debug \
//!     cargo test -p hort-adapters-storage --test s3_multipart -- --nocapture
//! ```
//!
//! **Honesty note for whoever runs this first in a Docker-capable
//! environment:** this bootstrap sequence (the `garage` CLI incantations
//! for layout assign/apply, bucket create, and key import) was written
//! from documentation/knowledge, not iteratively debugged against a live
//! Garage container — the sandbox this was authored in has no Docker
//! daemon available (verified: no `docker`/`podman` binary, no
//! `DOCKER_HOST`, no `docker.sock`, no relevant `dpkg` package). If the
//! bootstrap step itself fails, that is very likely a CLI-syntax
//! mismatch in `garage_bootstrap_script`, not the #53 defect this test
//! exists to catch — the panic messages below include full
//! stdout/stderr from every exec step for exactly that triage.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::env;
use std::time::Duration;

use hort_adapters_storage::builders::{build_s3_storage, S3StorageOpts};
use hort_domain::ports::storage::StoragePort;
use sha2::{Digest, Sha256};
use testcontainers::core::{CmdWaitFor, ContainerPort, ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

/// Garage S3 API port.
const S3_PORT: u16 = 3900;
/// Garage RPC port (node-to-node; single-node here, but the config still
/// binds it).
const RPC_PORT: u16 = 3901;

/// Pinned Garage image — MUST match the production version so the
/// reproduction is faithful. Prod runs **v2.2.0**; a multipart bug can be
/// version-specific, so testing against a different major (e.g. v1.0.1,
/// which passed) would not rule out a v2.2.0 regression. NOTE: the
/// `garage.toml` in [`garage_config`] and the CLI bootstrap in
/// [`garage_bootstrap_script`] were written for v1.x — the shell-free
/// container-mode rewrite (#54) must re-validate both against v2.2.0's
/// config/CLI. External mode (the working path today) is unaffected: the
/// operator provisions their own v2.2.0 Garage.
const GARAGE_IMAGE: &str = "dxflrs/garage";
const GARAGE_TAG: &str = "v2.2.0";

const TEST_BUCKET: &str = "hort-test-bucket";
/// Fixed (not CLI-generated) API credentials, imported via `garage key
/// import` — avoids parsing `garage key create`'s human-formatted stdout
/// for a generated ID/secret, which is one fewer fragile moving part in
/// an unverified bootstrap.
/// Garage access-key IDs are `GK` + 24 lowercase-hex chars (26 total);
/// secret keys are 64 lowercase-hex chars. `garage key import` validates
/// both formats, so these must be well-formed, not arbitrary strings.
const TEST_ACCESS_KEY: &str = "GK00112233445566778899aabb";
const TEST_SECRET_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// Garage's `rpc_secret` must be exactly 32 bytes hex-encoded (64 hex
/// chars). A wrong length makes the server refuse to start (the container
/// exits before bootstrap — the 409 "container is not running" symptom).
const RPC_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ADMIN_TOKEN: &str = "hort-test-admin-token";

/// Sentinel env var. Mirrors `HORT_TEST_NATS` / `DATABASE_URL`.
fn s3_gate_enabled() -> bool {
    env::var("HORT_TEST_S3").ok().as_deref() == Some("1")
}

/// The self-contained testcontainers mode ([`start_garage`]) is not yet
/// functional: `dxflrs/garage` is a shell-free (scratch) image, so the
/// in-container `garage`-CLI bootstrap needs a shell-free rewrite (driving
/// `/garage` directly, tracked with the backend-matrix work in #54). Until
/// then these tests require an **operator-provisioned** Garage via
/// `HORT_TEST_S3_ENDPOINT` (+ `HORT_TEST_S3_{ACCESS_KEY,SECRET_KEY,BUCKET}`).
/// Returns `true` (with a skip note on stderr) when the gate is on but no
/// external endpoint is configured, so a bare `HORT_TEST_S3=1` cleanly
/// skips rather than hitting the broken container bootstrap.
fn skip_without_external_endpoint() -> bool {
    if env::var("HORT_TEST_S3_ENDPOINT").is_err() {
        eprintln!(
            "SKIP s3_multipart: HORT_TEST_S3=1 but HORT_TEST_S3_ENDPOINT is unset. \
             Self-contained testcontainers mode is pending a shell-free Garage \
             bootstrap (see #54); point the test at an external Garage via \
             HORT_TEST_S3_ENDPOINT + HORT_TEST_S3_{{ACCESS_KEY,SECRET_KEY,BUCKET}}."
        );
        return true;
    }
    false
}

/// The `garage.toml` config baked into the container before start. A
/// minimal single-node (`replication_factor = 1`) config; SQLite metadata
/// engine (no extra dependencies inside the container).
fn garage_config() -> String {
    format!(
        r#"
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"

replication_factor = 1

rpc_bind_addr = "[::]:{RPC_PORT}"
rpc_public_addr = "127.0.0.1:{RPC_PORT}"
rpc_secret = "{RPC_SECRET}"

[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:{S3_PORT}"
root_domain = ".s3.garage.localhost"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "{ADMIN_TOKEN}"
"#
    )
}

/// The one-shot bootstrap script: wait for the node to be visible,
/// assign and apply a single-node layout, create the test bucket,
/// import a FIXED API key (not `key create` plus output-parsing), and
/// grant it full access. Runs as a single `exec` so the whole sequence
/// lives in one shell process — fewer round-trips than one `exec()` per
/// `garage` subcommand.
///
/// `set -ex` — abort on the first failing command; echo each command
/// before running it, so a bootstrap failure's panic (which prints this
/// exec's full stdout+stderr) shows exactly which step failed.
fn garage_bootstrap_script() -> String {
    format!(
        r#"set -ex
# Node ID is only stable once the server has fully started; poll `garage
# status` (rather than trusting the container's own log-line WaitFor
# alone) so this script is robust even if that heuristic fires early.
for i in $(seq 1 30); do
  if garage status >/tmp/status.out 2>&1; then
    break
  fi
  sleep 1
done
cat /tmp/status.out

NODE_ID=$(garage node id -q | cut -d'@' -f1)
echo "NODE_ID=$NODE_ID"

garage layout assign -z dc1 -c 1G "$NODE_ID"
garage layout apply --version 1

garage bucket create {TEST_BUCKET}
garage key import {TEST_ACCESS_KEY} {TEST_SECRET_KEY} -n hort-test-key -y
garage bucket allow --read --write --owner {TEST_BUCKET} --key {TEST_ACCESS_KEY}

echo "BOOTSTRAP_OK"
"#
    )
}

/// Start a `dxflrs/garage:v2.2.0` container, bootstrap a single-node
/// cluster + bucket + key inside it, and return the live container
/// handle plus the host-mapped S3 API port.
///
/// Panics (with full exec stdout/stderr) on any bootstrap failure —
/// there is no meaningful partial-success state for this test.
async fn start_garage() -> (ContainerAsync<GenericImage>, u16) {
    let config = garage_config();
    // Deliberately a loose, low-risk readiness heuristic (a fixed short
    // delay), NOT a precise log-message match — this sandbox has no
    // Docker to verify Garage's exact startup log wording against, so
    // asserting on it here would just be another unverified guess. True
    // readiness is instead confirmed by the bootstrap script's own
    // `garage status` retry-poll loop below, which is the part that
    // actually has to succeed for anything downstream to work.
    let container = GenericImage::new(GARAGE_IMAGE, GARAGE_TAG)
        .with_exposed_port(ContainerPort::Tcp(S3_PORT))
        .with_exposed_port(ContainerPort::Tcp(RPC_PORT))
        .with_wait_for(WaitFor::seconds(2))
        .with_startup_timeout(Duration::from_secs(60))
        .with_copy_to("/etc/garage.toml", config.into_bytes())
        .start()
        .await
        .expect("garage container starts");

    let mut bootstrap = container
        .exec(
            ExecCommand::new(["sh", "-c", &garage_bootstrap_script()])
                .with_cmd_ready_condition(CmdWaitFor::exit_code(0)),
        )
        .await
        .expect("bootstrap exec dispatches");
    let exit = bootstrap
        .exit_code()
        .await
        .expect("bootstrap exec reports an exit code");
    let stdout = String::from_utf8_lossy(
        &bootstrap
            .stdout_to_vec()
            .await
            .expect("bootstrap stdout reads"),
    )
    .into_owned();
    let stderr = String::from_utf8_lossy(
        &bootstrap
            .stderr_to_vec()
            .await
            .expect("bootstrap stderr reads"),
    )
    .into_owned();
    assert_eq!(
        exit,
        Some(0),
        "garage bootstrap script failed (exit={exit:?}).\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n\
         (see this test file's module doc — the bootstrap CLI \
         incantations are unverified against a live Garage in the \
         sandbox this was authored in; this is likely a CLI-syntax fix,\
         not the #53 defect)"
    );
    assert!(
        stdout.contains("BOOTSTRAP_OK"),
        "bootstrap script exited 0 but did not reach its final marker — \
         truncated run?\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );

    let port = container
        .get_host_port_ipv4(S3_PORT.tcp())
        .await
        .expect("garage container exposes host S3 port");
    (container, port)
}

/// Build an `ObjectStoreStorage` against the running Garage container.
fn build_storage(port: u16) -> hort_adapters_storage::ObjectStoreStorage {
    let endpoint = format!("http://127.0.0.1:{port}");
    let opts = S3StorageOpts {
        bucket: TEST_BUCKET,
        endpoint: Some(&endpoint),
        force_path_style: true,
        allow_http: true,
        region: "garage",
        access_key: TEST_ACCESS_KEY,
        secret_key: TEST_SECRET_KEY,
        extra_trust_anchors: None,
        sse_mode: None,
    };
    build_s3_storage(&opts).expect("S3 storage builds against the Garage endpoint")
}

/// Storage handle for the reproduction tests, in one of two modes:
///
/// - **External Garage** (fast diagnostic path): if `HORT_TEST_S3_ENDPOINT`
///   is set, build storage directly against it — the operator provisions
///   the Garage (a bucket + a key granted read/write). This sidesteps the
///   in-container `garage` CLI bootstrap entirely, which matters because
///   the `dxflrs/garage` image is shell-free (scratch), so the automated
///   testcontainers bootstrap has to drive `/garage` directly. Required
///   env: `HORT_TEST_S3_ENDPOINT` (e.g. `http://127.0.0.1:3900`),
///   `HORT_TEST_S3_ACCESS_KEY`, `HORT_TEST_S3_SECRET_KEY`,
///   `HORT_TEST_S3_BUCKET`; optional `HORT_TEST_S3_REGION` (default
///   `garage`). No container is returned.
/// - **testcontainers Garage** (self-contained): otherwise stand up
///   `dxflrs/garage` and bootstrap it via [`start_garage`]. The returned
///   `ContainerAsync` guard MUST be held for the test's duration.
async fn garage_storage() -> (
    Option<ContainerAsync<GenericImage>>,
    hort_adapters_storage::ObjectStoreStorage,
) {
    if let Ok(endpoint) = env::var("HORT_TEST_S3_ENDPOINT") {
        let access = env::var("HORT_TEST_S3_ACCESS_KEY")
            .expect("HORT_TEST_S3_ACCESS_KEY is required when HORT_TEST_S3_ENDPOINT is set");
        let secret = env::var("HORT_TEST_S3_SECRET_KEY")
            .expect("HORT_TEST_S3_SECRET_KEY is required when HORT_TEST_S3_ENDPOINT is set");
        let bucket = env::var("HORT_TEST_S3_BUCKET")
            .expect("HORT_TEST_S3_BUCKET is required when HORT_TEST_S3_ENDPOINT is set");
        let region = env::var("HORT_TEST_S3_REGION").unwrap_or_else(|_| "garage".to_string());
        let opts = S3StorageOpts {
            bucket: &bucket,
            endpoint: Some(&endpoint),
            force_path_style: true,
            allow_http: endpoint.starts_with("http://"),
            region: &region,
            access_key: &access,
            secret_key: &secret,
            extra_trust_anchors: None,
            sse_mode: None,
        };
        let storage = build_s3_storage(&opts)
            .expect("external S3 storage builds against HORT_TEST_S3_ENDPOINT");
        return (None, storage);
    }
    let (container, port) = start_garage().await;
    let storage = build_storage(port);
    (Some(container), storage)
}

/// Deterministic pseudo-random byte content of `len` bytes — not
/// all-zero (some object stores / proxies special-case sparse all-zero
/// bodies) and reproducible across runs without an external RNG
/// dependency.
fn deterministic_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0x53_1c2e_e837_3582u64; // arbitrary fixed seed
    while out.len() < len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ---------------------------------------------------------------------------
// The reproduction: a multipart put (> MIN_PART_SIZE) must complete well
// under a bounded timeout, and round-trip byte-for-byte.
// ---------------------------------------------------------------------------

/// ~12 MiB — forces at least 2 `put_part` calls (5 MiB `MIN_PART_SIZE`)
/// plus a final partial part, i.e. a genuine multi-part upload +
/// server-side `copy`, the exact shape #53's 76 MB layer hit.
///
/// Wrapped in a 45s bound: a hang becomes a clean, bounded test failure
/// (never a CI job hang) and directly answers the directive's Phase 1
/// question — did the hang reproduce against clean Garage, and (from the
/// `RUST_LOG=object_store=debug` trace this test's own doc-comment
/// instructs running with) which S3 op stalled.
#[tokio::test(flavor = "multi_thread")]
async fn multipart_put_roundtrips_large_blob() {
    if !s3_gate_enabled() || skip_without_external_endpoint() {
        return;
    }
    let (_container_guard, storage) = garage_storage().await;

    // Blob size is env-configurable (`HORT_TEST_S3_BLOB_MIB`, default 12) so
    // the size that reproduced in prod (#53's 76 MB layer) can be swept
    // against a live Garage without a rebuild. Any value > 5 (the
    // `MIN_PART_SIZE` MiB) forces a genuine multi-part upload.
    let blob_mib: usize = env::var("HORT_TEST_S3_BLOB_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(12);
    let content = deterministic_bytes(blob_mib * 1024 * 1024);
    let expected_hash_hex = format!("{:x}", Sha256::digest(&content));

    let content_for_stream = content.clone();
    let put_result = tokio::time::timeout(
        Duration::from_secs(45),
        storage.put(Box::new(std::io::Cursor::new(content_for_stream))),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "reproduces #53: multipart put did not complete in 45s \
             ({blob_mib} MiB body, 5 MiB MIN_PART_SIZE — a genuine multi-part upload)"
        )
    })
    .expect("multipart put succeeds against Garage");

    assert_eq!(
        put_result.hash.as_ref(),
        expected_hash_hex,
        "returned ContentHash must equal the independently-computed SHA-256"
    );
    assert_eq!(put_result.size_bytes, content.len() as u64);

    let mut read_back = Vec::new();
    let mut reader = storage
        .get(&put_result.hash)
        .await
        .expect("get succeeds for the just-put hash");
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut read_back)
        .await
        .expect("read-back succeeds");
    assert_eq!(
        read_back, content,
        "round-tripped bytes must match byte-for-byte"
    );
}

/// Control: a <5 MiB (single-part, no multipart machinery beyond the
/// trivial one-final-part case) blob must succeed — pins the observed
/// "small blobs work fine" boundary from the #53 report and proves the
/// harness (container, bootstrap, credentials, bucket) is sound
/// independent of the multipart question.
#[tokio::test(flavor = "multi_thread")]
async fn single_part_put_small_blob_control() {
    if !s3_gate_enabled() || skip_without_external_endpoint() {
        return;
    }
    let (_container_guard, storage) = garage_storage().await;

    let content = deterministic_bytes(1024 * 1024); // 1 MiB, well under 5 MiB MIN_PART_SIZE
    let expected_hash_hex = format!("{:x}", Sha256::digest(&content));

    let put_result = tokio::time::timeout(
        Duration::from_secs(45),
        storage.put(Box::new(std::io::Cursor::new(content.clone()))),
    )
    .await
    .expect("small-blob put must not even approach the 45s bound")
    .expect("single-part put succeeds against Garage");

    assert_eq!(put_result.hash.as_ref(), expected_hash_hex);

    let mut read_back = Vec::new();
    let mut reader = storage
        .get(&put_result.hash)
        .await
        .expect("get succeeds for the just-put hash");
    tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut read_back)
        .await
        .expect("read-back succeeds");
    assert_eq!(read_back, content);
}
