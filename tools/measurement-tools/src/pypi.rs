//! PyPI metadata-size measurement.
//!
//! ## What's measured
//!
//! We compute the *serialised JSON byte length* of the blob the v2 PyPI
//! ingest handler would store in the `artifact_metadata.metadata` column.
//! The handler (`crates/hort-http-pypi/src/lib.rs`) builds this from
//! twine multipart fields — today those are flat `String` entries plus a
//! separately-extracted `pkg_info` subobject. The most expensive fields
//! are the long `description` / `classifiers` / `project-urls`.
//!
//! ## Deviation from the real handler
//!
//! The v2 handler reads from the twine multipart *upload* request. There
//! is no upstream endpoint that serves the exact same shape, so we build
//! a representative equivalent from PyPI's JSON API
//! (`https://pypi.org/pypi/<name>/json`):
//!
//! - Take the `info` block — this covers the `pkg_info` subtree the
//!   simple-index read path actually queries (requires_python,
//!   classifiers, etc.). It is the dominant contributor to real upload
//!   payload size.
//! - Wrap it under a synthetic `{ "pkg_info": info, ...flat_fields }`
//!   shape matching what the upload handler currently stores.
//! - Serialise and measure byte length.
//!
//! This over-counts slightly relative to a real twine upload (the upload
//! path sometimes omits fields that the PyPI JSON API includes e.g.
//! `downloads` counters — rare). It under-counts when a project's README
//! is in `long_description` on upload but has been re-rendered into HTML
//! by the time PyPI JSON emits it (content length is usually comparable).
//! Net bias: within ±10%, acceptable for cap calibration.
//!
//! PyPI asks for respectful crawling via User-Agent (no strict numeric
//! limit). We apply a `--delay-ms` between requests and back off on 429.

use std::path::Path;
use std::time::Duration;

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::pypi::PyPiFormatHandler;
use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use crate::percentile::Summary;
use crate::sample_lists::PYPI_SEED;

/// Slim deserialisation of the PyPI JSON API response. We only care about
/// `info`; ignore `releases` / `urls` / `vulnerabilities` to keep memory
/// bounded on packages like `tensorflow` that have 100+ releases.
#[derive(Deserialize)]
struct PyPiResponse {
    info: serde_json::Value,
}

pub async fn run(
    client: &reqwest::Client,
    delay: Duration,
    sample_size: usize,
    out_dir: &Path,
) -> Result<()> {
    let handler = PyPiFormatHandler;
    info!(
        "format=pypi target_sample={} cap_placeholder={}B (from handler)",
        sample_size,
        handler.metadata_expected_max_bytes()
    );

    // CSV — flush as we go so an interrupted run leaves partial data.
    let csv_path = out_dir.join("015-metadata-sizes-pypi.csv");
    let mut csv = csv_writer(&csv_path)?;
    writeln!(csv, "name,bytes,http_status")?;

    let mut sizes: Vec<usize> = Vec::with_capacity(sample_size);
    let names: Vec<&str> = PYPI_SEED.iter().take(sample_size).copied().collect();
    let mut consecutive_429 = 0u32;

    for (idx, raw_name) in names.iter().enumerate() {
        // Use the real handler's normalisation for log parity with ingest.
        let normalised = handler.normalize_name(raw_name);
        let url = format!("https://pypi.org/pypi/{normalised}/json");

        match fetch_pypi_info(client, &url).await {
            Ok((bytes, status)) => {
                // Wrap `info` under `pkg_info` key — matches what our upload
                // handler stores (see crates/hort-http-pypi/src/lib.rs
                // where multipart fields go under `pkg_info`).
                let wrapped = serde_json::json!({
                    "pkg_info": bytes,
                    "name": raw_name,
                });
                let serialised =
                    serde_json::to_vec(&wrapped).context("serialising measured payload")?;
                sizes.push(serialised.len());
                writeln!(csv, "{},{},{}", raw_name, serialised.len(), status)?;
                consecutive_429 = 0;
            }
            Err(FetchErr::RateLimited) => {
                warn!("pypi rate-limited on {raw_name}; backing off 5s");
                consecutive_429 += 1;
                writeln!(csv, "{raw_name},,429")?;
                if consecutive_429 >= 5 {
                    warn!("five consecutive 429s — stopping PyPI measurement early");
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(FetchErr::NotFound) => {
                writeln!(csv, "{raw_name},,404")?;
            }
            Err(FetchErr::Other(e)) => {
                warn!("pypi fetch {raw_name}: {e:#}");
                writeln!(csv, "{raw_name},,ERR")?;
            }
        }

        if (idx + 1) % 50 == 0 {
            info!("pypi progress: {}/{}", idx + 1, names.len());
        }

        tokio::time::sleep(delay).await;
    }
    csv.flush()?;

    match Summary::from_slice(&mut sizes) {
        Some(s) => println!("PyPI metadata sizes (info wrapped as pkg_info): {s}"),
        None => println!("PyPI metadata sizes: no successful fetches"),
    }
    info!("pypi CSV written: {}", csv_path.display());

    Ok(())
}

async fn fetch_pypi_info(
    client: &reqwest::Client,
    url: &str,
) -> std::result::Result<(serde_json::Value, u16), FetchErr> {
    let res = client
        .get(url)
        .send()
        .await
        .map_err(|e| FetchErr::Other(anyhow::Error::new(e)))?;
    let status = res.status();
    if status.as_u16() == 429 {
        return Err(FetchErr::RateLimited);
    }
    if status.as_u16() == 404 {
        return Err(FetchErr::NotFound);
    }
    if !status.is_success() {
        return Err(FetchErr::Other(anyhow::anyhow!(
            "unexpected status {status} for {url}"
        )));
    }
    let parsed: PyPiResponse = res
        .json()
        .await
        .map_err(|e| FetchErr::Other(anyhow::Error::new(e)))?;
    Ok((parsed.info, status.as_u16()))
}

enum FetchErr {
    RateLimited,
    NotFound,
    Other(anyhow::Error),
}

use std::fs::File;
use std::io::{BufWriter, Write};

fn csv_writer(path: &Path) -> Result<BufWriter<File>> {
    let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    Ok(BufWriter::new(f))
}
