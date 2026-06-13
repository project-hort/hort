//! npm per-version packument entry size measurement.
//!
//! ## What's measured
//!
//! Our npm ingest handler stores the
//! per-version manifest — i.e. the `versions[v]` sub-object of the
//! packument. That's the JSON object containing `dependencies`,
//! `devDependencies`, `peerDependencies`, `scripts`, `engines`,
//! `bundledDependencies`, `_npmUser`, `dist`, etc.
//!
//! We fetch the packument at `https://registry.npmjs.org/<name>` and, for
//! every version, measure the byte length of that version's entry. The
//! per-crate statistic is the **max across versions** (same rationale as
//! cargo — an ingest cap constrains a single upload).
//!
//! ## Deviation from the real handler
//!
//! The real handler receives the packument in a publish request body
//! (client-side structured the same way), and stores `version_data`
//! unchanged. Upstream packuments include an extra `_npmUser` /
//! `_hasShrinkwrap` / signatures block that *may* be stripped before
//! ingest, but v2 today does not filter. Treat this as an **upper bound**
//! — real ingested sizes are ≤ what we measure here by a few percent.
//!
//! The npm registry does not have a published rate limit but asks for a
//! real User-Agent header. We apply `--delay-ms` between requests.

use std::path::Path;
use std::time::Duration;

use hort_domain::ports::format_handler::FormatHandler;
use hort_formats::npm::NpmFormatHandler;
use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::percentile::Summary;
use crate::sample_lists::NPM_SEED;

pub async fn run(
    client: &reqwest::Client,
    delay: Duration,
    sample_size: usize,
    out_dir: &Path,
) -> Result<()> {
    let handler = NpmFormatHandler;
    info!(
        "format=npm target_sample={} cap_placeholder={}B (from handler)",
        sample_size,
        handler.metadata_expected_max_bytes()
    );

    let csv_path = out_dir.join("015-metadata-sizes-npm.csv");
    let mut csv = csv_writer(&csv_path)?;
    writeln!(csv, "name,max_bytes_per_version,num_versions,http_status")?;

    let names: Vec<&str> = NPM_SEED.iter().take(sample_size).copied().collect();
    let mut sizes: Vec<usize> = Vec::with_capacity(names.len());
    let mut consecutive_429 = 0u32;

    for (idx, raw_name) in names.iter().enumerate() {
        // URL-encode scoped package slashes — npm accepts both `@scope/x`
        // and `@scope%2fx`. Use the raw form; reqwest handles it.
        let url = format!("https://registry.npmjs.org/{raw_name}");

        match fetch_packument(client, &url).await {
            Ok(packument) => {
                let versions = packument.get("versions").and_then(|v| v.as_object());
                let (max_bytes, num_versions) = match versions {
                    Some(m) => {
                        let mut max = 0usize;
                        for (_ver, version_data) in m {
                            // Serialise exactly as we'd store (no pretty
                            // print, no indent).
                            match serde_json::to_vec(version_data) {
                                Ok(bytes) => max = max.max(bytes.len()),
                                Err(e) => {
                                    warn!("npm {raw_name}: serialise version_data: {e}");
                                }
                            }
                        }
                        (max, m.len())
                    }
                    None => (0, 0),
                };
                if max_bytes > 0 {
                    sizes.push(max_bytes);
                    writeln!(csv, "{raw_name},{max_bytes},{num_versions},200")?;
                } else {
                    writeln!(csv, "{raw_name},,0,200")?;
                }
                consecutive_429 = 0;
            }
            Err(FetchErr::RateLimited) => {
                warn!("npm rate-limited on {raw_name}; backing off 5s");
                consecutive_429 += 1;
                writeln!(csv, "{raw_name},,,429")?;
                if consecutive_429 >= 5 {
                    warn!("five consecutive 429s — stopping npm measurement early");
                    break;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(FetchErr::NotFound) => {
                writeln!(csv, "{raw_name},,,404")?;
            }
            Err(FetchErr::Other(e)) => {
                warn!("npm fetch {raw_name}: {e:#}");
                writeln!(csv, "{raw_name},,,ERR")?;
            }
        }

        if (idx + 1) % 50 == 0 {
            info!("npm progress: {}/{}", idx + 1, names.len());
        }

        tokio::time::sleep(delay).await;
    }
    csv.flush()?;

    match Summary::from_slice(&mut sizes) {
        Some(s) => println!("npm per-version packument entry sizes (max per package): {s}"),
        None => println!("npm per-version packument entry sizes: no successful fetches"),
    }
    info!("npm CSV written: {}", csv_path.display());

    // Ensure the handler module is referenced beyond format_key() so clippy
    // doesn't flag the import as unused if we ever drop the info!() above.
    let _ = handler.format_key();

    Ok(())
}

async fn fetch_packument(
    client: &reqwest::Client,
    url: &str,
) -> std::result::Result<serde_json::Value, FetchErr> {
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
    let parsed: serde_json::Value = res
        .json()
        .await
        .map_err(|e| FetchErr::Other(anyhow::Error::new(e)))?;
    Ok(parsed)
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
