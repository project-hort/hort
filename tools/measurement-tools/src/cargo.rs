//! Cargo sparse-index entry size measurement.
//!
//! ## What's measured
//!
//! Cargo stores one JSON object *per version* of a crate in the sparse
//! index. Our v2 handler stores the same shape inside
//! `artifact_metadata.metadata`
//!
//! Note on body-cap vs per-entry semantics:
//! `CargoFormatHandler::metadata_expected_max_bytes()` is the **upstream-body
//! cap** — the cap on the full per-crate sparse-index page (one NDJSON
//! line per version), matching the npm and PyPI shape (see
//! `crates/hort-formats/src/npm.rs:287` and
//! `crates/hort-formats/src/pypi.rs:291`). It is calibrated to absorb
//! popular crates with hundreds of versions, currently 8 MiB.
//!
//! The per-entry measurements collected by this tool sit *below* that
//! body cap: they are useful for sizing the in-database metadata
//! storage (one row per version) and for the `parse_publish_body`
//! `PUBLISH_META_CAP` (64 KiB) in `crates/hort-http-cargo/src/lib.rs`,
//! since the publish frame carries a single version's metadata,
//! structurally comparable to one sparse-index entry. They are NOT
//! the upstream-body cap. Re-introducing a per-entry cap on the upstream
//! parse path is out of scope here.
//!
//! ## Source
//!
//! - List top-downloaded crates via
//!   `https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=N`.
//!   5 pages ⇒ 500 names.
//! - For each crate, fetch the sparse index file at
//!   `https://index.crates.io/<prefix>/<name>` (or the 1-/2-/3-char
//!   prefix variant). Each line is a per-version JSON object — we read
//!   each, measure its byte length, and keep the **max** for that crate.
//!
//! The sparse index entry is *itself* the shape we'd store, so there's
//! effectively zero deviation from the real ingest path here (modulo
//! whitespace — sparse index is minified JSON, which is what our handler
//! would emit via `serde_json::to_vec`).

use std::path::Path;
use std::time::Duration;

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::cargo::{index_path_for, CargoFormatHandler};
use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use crate::percentile::Summary;

#[derive(Deserialize)]
struct CratesListResponse {
    crates: Vec<CrateBrief>,
}

#[derive(Deserialize)]
struct CrateBrief {
    name: String,
}

pub async fn run(
    client: &reqwest::Client,
    delay: Duration,
    sample_size: usize,
    out_dir: &Path,
) -> Result<()> {
    let handler = CargoFormatHandler;
    info!(
        "format=cargo target_sample={} cap_placeholder={}B (from handler)",
        sample_size,
        handler.metadata_expected_max_bytes()
    );

    // Page through the crates.io API 100 at a time.
    let mut names: Vec<String> = Vec::with_capacity(sample_size);
    let per_page = 100usize;
    let mut page = 1usize;
    while names.len() < sample_size {
        let url = format!(
            "https://crates.io/api/v1/crates?sort=downloads&per_page={per_page}&page={page}"
        );
        let res = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        if !res.status().is_success() {
            anyhow::bail!("crates.io list API returned {} for {url}", res.status());
        }
        let parsed: CratesListResponse =
            res.json().await.with_context(|| format!("parsing {url}"))?;
        if parsed.crates.is_empty() {
            break;
        }
        for c in parsed.crates {
            names.push(c.name);
            if names.len() >= sample_size {
                break;
            }
        }
        page += 1;
        tokio::time::sleep(delay).await;
    }

    info!("cargo: collected {} crate names", names.len());

    let csv_path = out_dir.join("015-metadata-sizes-cargo.csv");
    let mut csv = csv_writer(&csv_path)?;
    writeln!(csv, "name,max_bytes_per_version,num_versions,http_status")?;

    let mut sizes: Vec<usize> = Vec::with_capacity(names.len());
    let mut consecutive_429 = 0u32;

    for (idx, raw_name) in names.iter().enumerate() {
        let normalised = handler.normalize_name(raw_name);
        let index_rel = index_path_for(&normalised);
        let url = format!("https://index.crates.io/{index_rel}");

        match fetch_cargo_index(client, &url).await {
            Ok(body) => {
                let mut max_bytes = 0usize;
                let mut num_versions = 0usize;
                for line in body.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    num_versions += 1;
                    // The line IS the shape we'd store — measure its byte
                    // length directly. Validating it parses as JSON guards
                    // against a partial response slipping through.
                    let _: serde_json::Value = match serde_json::from_str(trimmed) {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("cargo {raw_name}: bad sparse-index line: {e}");
                            continue;
                        }
                    };
                    max_bytes = max_bytes.max(trimmed.len());
                }
                if max_bytes > 0 {
                    sizes.push(max_bytes);
                    writeln!(csv, "{raw_name},{max_bytes},{num_versions},200")?;
                } else {
                    writeln!(csv, "{raw_name},,0,200")?;
                }
                consecutive_429 = 0;
            }
            Err(FetchErr::RateLimited) => {
                warn!("cargo rate-limited on {raw_name}; backing off 5s");
                consecutive_429 += 1;
                writeln!(csv, "{raw_name},,,429")?;
                if consecutive_429 >= 5 {
                    warn!("five consecutive 429s — stopping cargo measurement early");
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(FetchErr::NotFound) => {
                writeln!(csv, "{raw_name},,,404")?;
            }
            Err(FetchErr::Other(e)) => {
                warn!("cargo fetch {raw_name}: {e:#}");
                writeln!(csv, "{raw_name},,,ERR")?;
            }
        }

        if (idx + 1) % 50 == 0 {
            info!("cargo progress: {}/{}", idx + 1, names.len());
        }

        tokio::time::sleep(delay).await;
    }
    csv.flush()?;

    match Summary::from_slice(&mut sizes) {
        Some(s) => println!("Cargo sparse-index entry sizes (max per crate): {s}"),
        None => println!("Cargo sparse-index entry sizes: no successful fetches"),
    }
    info!("cargo CSV written: {}", csv_path.display());

    Ok(())
}

async fn fetch_cargo_index(
    client: &reqwest::Client,
    url: &str,
) -> std::result::Result<String, FetchErr> {
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
    let body = res
        .text()
        .await
        .map_err(|e| FetchErr::Other(anyhow::Error::new(e)))?;
    Ok(body)
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
