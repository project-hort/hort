//! Wire types for the OSV.dev `/v1/querybatch` endpoint.
//!
//! Reference: <https://google.github.io/osv.dev/post-v1-querybatch/>.
//!
//! Only the subset of fields we consume is modelled; OSV's response
//! carries additional fields (e.g. `next_page_token`) that are
//! deliberately ignored. `serde` is permissive on unknown fields by
//! default — we keep it that way so an OSV schema addition does not
//! break the adapter.

use serde::{Deserialize, Serialize};

// ----- Request shapes -------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct OsvBatchRequest {
    pub queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OsvQuery {
    pub package: OsvPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OsvPackage {
    pub name: String,
    pub ecosystem: String,
}

// ----- Response shapes ------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct OsvBatchResponse {
    /// One result entry per input query, in input order. The OSV docs
    /// guarantee this ordering (`results[i]` corresponds to
    /// `queries[i]`), which is what the batch caller relies on.
    #[serde(default)]
    pub results: Vec<OsvResult>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvResult {
    /// Vulnerabilities affecting the queried package. Absent or empty
    /// means "no advisories for this component."
    #[serde(default)]
    pub vulns: Vec<OsvVuln>,
}

/// One vulnerability entry from `querybatch`. Note that `querybatch`
/// returns *abbreviated* records — the full vulnerability detail
/// (severity score, references) requires a follow-up `/v1/vulns/{id}`
/// call which we deliberately skip in v1.
#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvVuln {
    /// Canonical vulnerability id (e.g. `GHSA-…`, `OSV-…`,
    /// `CVE-…`). May be absent in malformed payloads — defaulting to
    /// the empty string lets the parsing layer reject the finding via
    /// `Finding::validate()` rather than panicking.
    #[serde(default)]
    pub id: String,

    /// One-line summary (often present on `querybatch` responses).
    #[serde(default)]
    pub summary: Option<String>,

    /// Long-form description (rarely present on `querybatch`).
    #[serde(default)]
    pub details: Option<String>,

    /// Cross-feed aliases — typically the CVE id when the primary
    /// record is a GHSA/OSV id. Surfaced as reference URLs by
    /// `vuln_to_finding` (parity with the scanner adapter at
    /// `crates/hort-adapters-scanner-osv/src/parse.rs:311..326`) so
    /// operators see the CVE id even when the primary OSV id is a
    /// GHSA. The advisory-watch task also consumes these.
    #[serde(default)]
    pub aliases: Vec<String>,

    /// CVSS / severity vectors. May be absent on `querybatch`; when
    /// present, each entry has a `score` field which is the textual
    /// CVSS vector (NOT the numeric base score). v1 falls back to
    /// `database_specific.severity` instead of decoding the vector.
    #[serde(default)]
    #[allow(dead_code)]
    pub severity: Vec<OsvSeverity>,

    /// `database_specific.severity` is the most reliable source of a
    /// human-readable severity label on `querybatch` payloads.
    #[serde(default)]
    pub database_specific: Option<OsvDatabaseSpecific>,

    /// Affected-package ranges — used to extract `fixed_versions`.
    #[serde(default)]
    pub affected: Vec<OsvAffected>,

    /// Reference URLs (advisory pages, patch links). Often absent on
    /// `querybatch`; we capture whatever comes through.
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvSeverity {
    /// CVSS vector string, e.g. `"CVSS:3.1/AV:N/AC:L/..."`. The base
    /// score is encoded inside the vector; computing it requires a
    /// CVSS calculator. v1 falls back to `database_specific.severity`
    /// instead.
    #[serde(default)]
    #[allow(dead_code)] // captured for forward-compat; not used by v1 mapper.
    pub score: Option<String>,

    /// Vector type — `"CVSS_V3"`, `"CVSS_V4"`, etc. Tracked for
    /// forward-compatibility; v1 does not use the value.
    #[serde(default, rename = "type")]
    #[allow(dead_code)]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvDatabaseSpecific {
    /// Free-form severity label. May be `"HIGH"`, `"7.5 HIGH"`,
    /// `"7.5"`, or absent. Parsed by `severity::label_to_severity`.
    #[serde(default)]
    pub severity: Option<String>,

    /// RustSec informational class — `"unmaintained"`, `"unsound"`, or
    /// `"notice"`. Present only on informational advisories, which carry
    /// no CVSS score by design. A recognised class routes the finding
    /// onto the non-enforcing negligible lane rather than the SUP-4
    /// Critical fail-closed fallback. Parity with the scanner-osv
    /// adapter's `OsvDatabaseSpecific`.
    #[serde(default)]
    pub informational: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvAffected {
    #[serde(default)]
    pub ranges: Vec<OsvRange>,

    /// Per-`affected[]` `database_specific` block. Real RustSec OSV
    /// records place the `informational` discriminator
    /// (`unmaintained` / `unsound` / `notice`) here, NOT on the
    /// vulnerability-level `database_specific`. Present only on full
    /// records (the bulk-archive path); `/v1/querybatch` returns
    /// abbreviated records without `affected[].database_specific`, so
    /// this field is `None` on querybatch responses by design — that is
    /// an inherent querybatch limitation, not a bug. See
    /// `crates/hort-adapters-scanner-osv/tests/fixtures/informational_unmaintained.json`.
    #[serde(default)]
    pub database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvRange {
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvRangeEvent {
    /// `introduced` / `fixed` event marker. We only consume `fixed`;
    /// other events are tolerated and ignored.
    #[serde(default)]
    pub fixed: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct OsvReference {
    #[serde(default)]
    pub url: String,
}
