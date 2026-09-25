//! Human-readable rendering of a retention preview, of an execution
//! result, and of the difference between two previews.
//!
//! The text this module produces *is* the safety mechanism: it is the
//! only place an operator sees what a retention run would remove before
//! authorising it. Three rules hold everything here together.
//!
//! **A count is never allowed to read as a size.** `51,535` artifact
//! rows and the bytes those rows would free are different quantities
//! that will not agree, because one stored blob can be referenced by
//! many artifact rows and is reclaimed only when the last of them goes
//! away. Every count is labelled as a count at the point it is printed,
//! and the two never share a column.
//!
//! **An unmeasured size is stated, never implied.** When the server did
//! not measure the reclaimable bytes it says so and why. That renders as
//! the words "not measured" plus the reason — never `0`, never a blank,
//! never a dash, each of which reads as "there is nothing to free".
//!
//! **Truncation is a header, not a footnote.** A `partial` sweep stopped
//! before the end of the artifact table, so every total below it
//! undercounts. That belongs where the operator cannot miss it, above
//! the numbers it qualifies.

use std::collections::BTreeMap;

use crate::output::format_table_rows;

use super::dto::{FreedBytes, PreviewBody, PreviewGroup, RetentionRunSummary};

/// Group a non-negative integer with thousands separators.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Render a measured byte count as a binary-prefix size plus its exact
/// value, explicitly marked as measured so it can never be mistaken for
/// an estimate.
pub fn measured_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{} {} (measured)", count(bytes), byte_noun(bytes));
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!(
        "{value:.2} {unit} ({} {}, measured)",
        count(bytes),
        byte_noun(bytes)
    )
}

/// Singular/plural for a byte count, so a one-byte figure does not read
/// as a typo in an output whose whole job is to be trusted.
fn byte_noun(n: u64) -> &'static str {
    if n == 1 {
        "byte"
    } else {
        "bytes"
    }
}

/// One line's worth of byte accounting, measured or explicitly not.
fn bytes_phrase(freed: &FreedBytes) -> String {
    match freed.measured() {
        Some(bytes) => measured_bytes(bytes),
        None => format!(
            "NOT MEASURED — {}",
            freed
                .omission_reason()
                .unwrap_or("the server gave no reason")
        ),
    }
}

/// A short form for the delta table, where the reason is carried in its
/// own row rather than inline.
fn bytes_cell(freed: &FreedBytes) -> String {
    match freed.measured() {
        Some(bytes) => format!("{} {}", count(bytes), byte_noun(bytes)),
        None => "not measured".to_string(),
    }
}

/// Everything the preview header needs that is not in the summary
/// itself.
#[derive(Debug, Clone)]
pub struct JobFacts {
    pub job_id: String,
    pub job_status: String,
    pub completed_at: Option<String>,
    /// The server answered `200 OK` rather than `202 Accepted`: this job
    /// was **not** created by our request, it is an earlier same-day
    /// invocation the server's idempotency layer handed back.
    pub deduplicated: bool,
}

/// Render the coverage line. `partial` is spelled out in full because an
/// operator who skims past it is reading undercounted totals as if they
/// were the whole picture.
fn coverage_block(summary: &RetentionRunSummary) -> String {
    if summary.coverage_is_partial() {
        // Name the server's own word only when it is not the expected
        // `partial`: "PARTIAL (partial)" is noise, but a coverage word
        // this CLI does not know is something the operator should see
        // verbatim rather than have translated for them.
        let verbatim = match summary.coverage.as_str() {
            "partial" => String::new(),
            "" => " (the server reported no coverage at all)".to_string(),
            other => format!(" (the server said {other:?})"),
        };
        format!(
            "  coverage    PARTIAL{verbatim} — the sweep stopped at its per-run batch cap\n\
             \x20             with artifacts still unexamined. Every figure below counts\n\
             \x20             only what it reached; the real totals are larger.\n"
        )
    } else {
        "  coverage    complete — the sweep reached the end of the candidate set.\n".to_string()
    }
}

fn dedup_block(facts: &JobFacts) -> String {
    if !facts.deduplicated {
        return String::new();
    }
    "\n  NOTE  The server did not run a new sweep for this request — it answered\n\
     \x20       with an EARLIER sweep from today, replayed. What is shown below is\n\
     \x20       not a fresh observation of the current state.\n"
        .to_string()
}

/// Render the whole dry-run preview.
pub fn render_preview(
    title: &str,
    facts: &JobFacts,
    summary: &RetentionRunSummary,
    sample_rows_to_show: usize,
) -> String {
    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str(&format!("  task job    {}\n", facts.job_id));
    out.push_str(&format!("  job status  {}\n", facts.job_status));
    out.push_str(&format!(
        "  mode        {}\n",
        if summary.mode.is_empty() {
            "(unreported)"
        } else {
            summary.mode.as_str()
        }
    ));
    if let Some(ref at) = facts.completed_at {
        out.push_str(&format!("  finished    {at}\n"));
    }
    out.push_str(&coverage_block(summary));
    out.push_str(&dedup_block(facts));

    let Some(preview) = summary.preview.as_ref() else {
        out.push_str(
            "\nThis job carries no preview object. It was not a dry run, so there is\n\
             nothing here to confirm against.\n",
        );
        return out;
    };

    out.push_str("\nWHAT WOULD BE EXPIRED\n");
    out.push_str(&format!(
        "  artifact rows       {:>12}   artifact records — a count, not a size\n",
        count(preview.rows)
    ));
    out.push_str(&format!(
        "  distinct contents   {:>12}   distinct stored blobs those rows point at\n",
        count(preview.distinct_contents)
    ));
    out.push_str(&format!(
        "  storage freed       {}\n",
        bytes_phrase(&preview.freed_bytes)
    ));
    out.push_str(
        "\n  Rows and bytes are different quantities and will not agree. One stored\n\
         \x20 blob can be referenced by many artifact rows, so expiring the rows above\n\
         \x20 frees only those blobs that lose their last reference. hort prints a size\n\
         \x20 only when it has measured one — there is no estimate anywhere in this\n\
         \x20 output, and a row count is never a storage figure.\n",
    );

    out.push_str("\nSWEEP\n");
    for (label, value) in [
        ("active policies", summary.policies),
        ("(policy, artifact) pairs evaluated", summary.evaluated),
        ("pairs that matched", summary.expired),
        (
            "already expired by the same policy",
            summary.already_expired,
        ),
        ("skipped — GC-protected", summary.skipped_protected),
        ("skipped — scan data too stale", summary.skipped_stale_scan),
        ("pairs that errored", summary.errors),
    ] {
        out.push_str(&format!("  {label:<36}{:>12}\n", count(value)));
    }

    out.push_str("\nBY POLICY AND REPOSITORY\n");
    out.push_str(&render_groups(&preview.groups));
    out.push_str(
        "\n  There is deliberately no byte column here. A blob is freed only when the\n\
         \x20 last reference to it anywhere goes away, which no single policy or\n\
         \x20 repository group can decide on its own; the measured figure above is a\n\
         \x20 whole-run one.\n",
    );

    out.push_str(&render_sample(preview, sample_rows_to_show));
    out
}

fn render_groups(groups: &[PreviewGroup]) -> String {
    if groups.is_empty() {
        return "  (no policy matched anything)\n".to_string();
    }
    let rows: Vec<Vec<String>> = groups
        .iter()
        .map(|g| {
            vec![
                g.policy_name.clone(),
                repository_label(&g.repository_key, &g.repository_id),
                count(g.rows),
                count(g.distinct_contents),
            ]
        })
        .collect();
    indent(&format_table_rows(
        &["POLICY", "REPOSITORY", "ARTIFACT ROWS", "DISTINCT CONTENTS"],
        &rows,
    ))
}

/// Name a repository the way an operator writes it into a policy.
///
/// The key is `repositories.key`, which is what a policy's
/// `metadata.name` resolves against. A UUID is not an identifier an
/// operator can act on, so it is shown only as the explicit fallback for
/// a server too old to send a key — and then it is labelled as such, so
/// nobody mistakes it for something they could type back.
pub fn repository_label(key: &str, id: &str) -> String {
    if key.is_empty() {
        format!("(no key reported; id {id})")
    } else {
        key.to_string()
    }
}

fn render_sample(preview: &PreviewBody, show: usize) -> String {
    let recorded = preview.sample.len();
    if recorded == 0 || show == 0 {
        return String::new();
    }
    let shown = show.min(recorded);
    let mut header = format!("\nSAMPLE — {shown} of the {recorded} rows recorded");
    if let Some(limit) = preview.sample_limit {
        if recorded as u64 >= limit {
            header.push_str(&format!(" (the server records at most {})", count(limit)));
        }
    }
    header.push_str(&format!("; {} rows match in total\n", count(preview.rows)));

    let policy_names: BTreeMap<&str, &str> = preview
        .groups
        .iter()
        .map(|g| (g.policy_id.as_str(), g.policy_name.as_str()))
        .collect();

    let rows: Vec<Vec<String>> = preview
        .sample
        .iter()
        .take(shown)
        .map(|row| {
            vec![
                policy_names
                    .get(row.policy_id.as_str())
                    .copied()
                    .unwrap_or("(unknown policy)")
                    .to_string(),
                repository_label(&row.repository_key, &row.repository_id),
                row.name.clone(),
                row.version.clone().unwrap_or_else(|| "-".to_string()),
                age(row.age_seconds),
            ]
        })
        .collect();

    header.push_str(&indent(&format_table_rows(
        &["POLICY", "REPOSITORY", "NAME", "VERSION", "AGE"],
        &rows,
    )));
    header
}

/// Render an age in units an operator reads at a glance.
pub fn age(seconds: i64) -> String {
    if seconds < 0 {
        return "(future)".to_string();
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h")
    } else {
        format!("{}m", seconds / 60)
    }
}

fn indent(table: &str) -> String {
    table
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect::<String>()
}

// ---------------------------------------------------------------------------
// Delta between two previews
// ---------------------------------------------------------------------------

/// One `(policy, repository)` group's movement between two previews.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupDelta {
    pub policy_id: String,
    pub policy_name: String,
    pub repository_id: String,
    pub repository_key: String,
    /// `(rows, distinct_contents)` in the baseline, or `None` when the
    /// group did not exist there.
    pub baseline: Option<(u64, u64)>,
    /// The same in the fresh preview, or `None` when it has gone.
    pub fresh: Option<(u64, u64)>,
}

impl GroupDelta {
    pub fn changed(&self) -> bool {
        self.baseline != self.fresh
    }
}

/// The difference between a baseline preview and a fresh one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewDelta {
    pub baseline_rows: u64,
    pub fresh_rows: u64,
    pub baseline_distinct: u64,
    pub fresh_distinct: u64,
    pub baseline_bytes: FreedBytes,
    pub fresh_bytes: FreedBytes,
    pub baseline_coverage: String,
    pub fresh_coverage: String,
    pub groups: Vec<GroupDelta>,
}

impl PreviewDelta {
    /// `true` when anything an operator would act on moved.
    pub fn changed(&self) -> bool {
        self.baseline_rows != self.fresh_rows
            || self.baseline_distinct != self.fresh_distinct
            || self.baseline_bytes != self.fresh_bytes
            || self.baseline_coverage != self.fresh_coverage
            || self.groups.iter().any(GroupDelta::changed)
    }
}

/// Compute the difference between two run summaries.
///
/// A summary with no `preview` object contributes zeroes rather than
/// failing, so comparing against a job that turned out not to be a dry
/// run still produces a visible difference instead of silence.
pub fn diff(baseline: &RetentionRunSummary, fresh: &RetentionRunSummary) -> PreviewDelta {
    let empty = PreviewBody::default();
    let b = baseline.preview.as_ref().unwrap_or(&empty);
    let f = fresh.preview.as_ref().unwrap_or(&empty);

    let mut keys: Vec<(String, String)> = Vec::new();
    let mut baseline_groups: BTreeMap<(String, String), &PreviewGroup> = BTreeMap::new();
    let mut fresh_groups: BTreeMap<(String, String), &PreviewGroup> = BTreeMap::new();
    for g in &b.groups {
        baseline_groups.insert(g.key(), g);
    }
    for g in &f.groups {
        fresh_groups.insert(g.key(), g);
    }
    for key in baseline_groups.keys().chain(fresh_groups.keys()) {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    keys.sort();

    let groups = keys
        .into_iter()
        .map(|key| {
            let bg = baseline_groups.get(&key);
            let fg = fresh_groups.get(&key);
            // Prefer the fresh naming: it is the newer read of the
            // repository's key, and a rename between the two previews is
            // itself something the operator should see stated currently.
            let named = fg.or(bg).expect("a key comes from one side or the other");
            GroupDelta {
                policy_id: named.policy_id.clone(),
                policy_name: named.policy_name.clone(),
                repository_id: named.repository_id.clone(),
                repository_key: named.repository_key.clone(),
                baseline: bg.map(|g| (g.rows, g.distinct_contents)),
                fresh: fg.map(|g| (g.rows, g.distinct_contents)),
            }
        })
        .collect();

    PreviewDelta {
        baseline_rows: b.rows,
        fresh_rows: f.rows,
        baseline_distinct: b.distinct_contents,
        fresh_distinct: f.distinct_contents,
        baseline_bytes: b.freed_bytes.clone(),
        fresh_bytes: f.freed_bytes.clone(),
        baseline_coverage: baseline.coverage.clone(),
        fresh_coverage: fresh.coverage.clone(),
        groups,
    }
}

fn signed(before: u64, after: u64) -> String {
    match after.cmp(&before) {
        std::cmp::Ordering::Equal => "unchanged".to_string(),
        std::cmp::Ordering::Greater => format!("+{}", count(after - before)),
        std::cmp::Ordering::Less => format!("-{}", count(before - after)),
    }
}

/// Render the difference between the named baseline and the fresh
/// preview.
pub fn render_delta(delta: &PreviewDelta, baseline_job: &str, fresh_job: &str) -> String {
    let mut out = String::new();
    if delta.changed() {
        out.push_str("WHAT CHANGED SINCE THE PREVIEW YOU NAMED\n");
    } else {
        out.push_str("NOTHING CHANGED SINCE THE PREVIEW YOU NAMED\n");
    }
    out.push_str(&format!("  baseline preview  {baseline_job}\n"));
    out.push_str(&format!("  fresh preview     {fresh_job}\n\n"));

    let rows = vec![
        vec![
            "artifact rows (a count, not a size)".to_string(),
            count(delta.baseline_rows),
            count(delta.fresh_rows),
            signed(delta.baseline_rows, delta.fresh_rows),
        ],
        vec![
            "distinct contents".to_string(),
            count(delta.baseline_distinct),
            count(delta.fresh_distinct),
            signed(delta.baseline_distinct, delta.fresh_distinct),
        ],
        vec![
            "storage freed".to_string(),
            bytes_cell(&delta.baseline_bytes),
            bytes_cell(&delta.fresh_bytes),
            byte_change(&delta.baseline_bytes, &delta.fresh_bytes),
        ],
        vec![
            "coverage".to_string(),
            coverage_word(&delta.baseline_coverage),
            coverage_word(&delta.fresh_coverage),
            if delta.baseline_coverage == delta.fresh_coverage {
                "unchanged".to_string()
            } else {
                "changed".to_string()
            },
        ],
    ];
    out.push_str(&indent(&format_table_rows(
        &["FIGURE", "BASELINE", "NOW", "CHANGE"],
        &rows,
    )));

    if delta.fresh_bytes.measured().is_none() {
        out.push_str(&format!(
            "\n  The fresh preview did not measure a size: {}.\n\
             \x20 No estimate is substituted.\n",
            delta
                .fresh_bytes
                .omission_reason()
                .unwrap_or("the server gave no reason")
        ));
    }

    let moved: Vec<&GroupDelta> = delta.groups.iter().filter(|g| g.changed()).collect();
    if !moved.is_empty() {
        out.push_str("\n  BY POLICY AND REPOSITORY (only the groups that moved)\n");
        let rows: Vec<Vec<String>> = moved
            .iter()
            .map(|g| {
                vec![
                    g.policy_name.clone(),
                    repository_label(&g.repository_key, &g.repository_id),
                    pair_change(g.baseline.map(|(r, _)| r), g.fresh.map(|(r, _)| r)),
                    pair_change(g.baseline.map(|(_, d)| d), g.fresh.map(|(_, d)| d)),
                ]
            })
            .collect();
        out.push_str(&indent(&indent(&format_table_rows(
            &["POLICY", "REPOSITORY", "ARTIFACT ROWS", "DISTINCT CONTENTS"],
            &rows,
        ))));
    }
    out
}

/// Describe how the byte accounting moved.
///
/// A signed figure only when both sides were actually measured: a
/// difference computed against a run that measured nothing would be an
/// invented number, which is the one thing this output never produces.
fn byte_change(before: &FreedBytes, after: &FreedBytes) -> String {
    match (before.measured(), after.measured()) {
        (Some(b), Some(a)) if b == a => "unchanged".to_string(),
        (Some(b), Some(a)) => format!("{} {}", signed(b, a), byte_noun(a.abs_diff(b))),
        (Some(_), None) => "no longer measured".to_string(),
        (None, Some(_)) => "now measured".to_string(),
        (None, None) if before == after => "unchanged".to_string(),
        (None, None) => "still not measured".to_string(),
    }
}

fn coverage_word(raw: &str) -> String {
    if raw.is_empty() {
        "(unreported)".to_string()
    } else {
        raw.to_string()
    }
}

fn pair_change(before: Option<u64>, after: Option<u64>) -> String {
    match (before, after) {
        (Some(b), Some(a)) if b == a => count(a),
        (Some(b), Some(a)) => format!("{} -> {} ({})", count(b), count(a), signed(b, a)),
        (None, Some(a)) => format!("new: {}", count(a)),
        (Some(b), None) => format!("gone (was {})", count(b)),
        (None, None) => "-".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

/// Render the outcome of the execute-mode run.
pub fn render_execution(facts: &JobFacts, summary: &RetentionRunSummary) -> String {
    let mut out = String::from("RETENTION EXECUTED\n");
    out.push_str(&format!("  task job    {}\n", facts.job_id));
    out.push_str(&format!("  job status  {}\n", facts.job_status));
    if let Some(ref at) = facts.completed_at {
        out.push_str(&format!("  finished    {at}\n"));
    }
    out.push_str(&coverage_block(summary));
    if facts.deduplicated {
        out.push_str(
            "\n  NOTE  The server deduplicated this execution against an earlier one\n\
             \x20       from the same UTC day: no new sweep was started by your\n\
             \x20       confirmation, and the figures below belong to that earlier run.\n",
        );
    }
    out.push_str("\nRESULT\n");
    for (label, value) in [
        ("active policies", summary.policies),
        ("(policy, artifact) pairs evaluated", summary.evaluated),
        ("artifact rows expired now", summary.expired),
        (
            "already expired by the same policy",
            summary.already_expired,
        ),
        ("skipped — GC-protected", summary.skipped_protected),
        ("skipped — scan data too stale", summary.skipped_stale_scan),
        ("pairs that errored", summary.errors),
    ] {
        out.push_str(&format!("  {label:<36}{:>12}\n", count(value)));
    }
    out.push_str(
        "\n  Expiry marks artifact records; it does not itself delete stored bytes.\n\
         \x20 The separate purge stage reclaims a blob once its last reference is gone.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::retention::dto::{PreviewSampleRow, OMITTED_BYTES_REASON};

    fn group(policy: &str, repo_key: &str, rows: u64, distinct: u64) -> PreviewGroup {
        PreviewGroup {
            policy_id: format!("policy-{policy}"),
            policy_name: policy.to_string(),
            repository_id: format!("11111111-0000-0000-0000-{repo_key:0>12}"),
            repository_key: repo_key.to_string(),
            rows,
            distinct_contents: distinct,
        }
    }

    fn summary(rows: u64, distinct: u64, freed: FreedBytes, coverage: &str) -> RetentionRunSummary {
        RetentionRunSummary {
            mode: "dry_run".into(),
            coverage: coverage.into(),
            policies: 1,
            evaluated: 100,
            expired: rows,
            preview: Some(PreviewBody {
                rows,
                distinct_contents: distinct,
                freed_bytes: freed,
                groups: vec![group("npm-90d", "npmproxy", rows, distinct)],
                sample: vec![PreviewSampleRow {
                    artifact_id: "aaaa".into(),
                    policy_id: "policy-npm-90d".into(),
                    repository_id: "11111111-0000-0000-0000-0000npmproxy".into(),
                    repository_key: "npmproxy".into(),
                    name: "left-pad".into(),
                    version: Some("1.3.0".into()),
                    age_seconds: 98_765,
                }],
                sample_limit: Some(500),
            }),
            ..RetentionRunSummary::default()
        }
    }

    fn facts() -> JobFacts {
        JobFacts {
            job_id: "job-1".into(),
            job_status: "completed".into(),
            completed_at: Some("2026-09-25T11:02:14Z".into()),
            deduplicated: false,
        }
    }

    #[test]
    fn count_groups_thousands() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(51_535), "51,535");
        assert_eq!(count(1_288_490_188), "1,288,490,188");
    }

    #[test]
    fn measured_bytes_carries_the_exact_value_and_says_it_is_measured() {
        assert_eq!(measured_bytes(512), "512 bytes (measured)");
        let gib = measured_bytes(1_288_490_188);
        assert!(gib.contains("GiB"), "{gib}");
        assert!(gib.contains("1,288,490,188 bytes"), "{gib}");
        assert!(gib.contains("measured"), "{gib}");
    }

    #[test]
    fn an_omitted_size_says_not_measured_with_the_reason() {
        let rendered = bytes_phrase(&FreedBytes::Omitted {
            reason: OMITTED_BYTES_REASON.into(),
        });
        // The whole phrase is the banner plus the server's reason
        // verbatim. Stated as an equality rather than as "contains no
        // `0`": the server's reason legitimately carries the bound and
        // the observed count, so digits inside it are the explanation,
        // not a figure hort invented. What must never appear is a byte
        // figure of our own, and there is no room for one here.
        assert_eq!(
            rendered,
            format!("NOT MEASURED — {OMITTED_BYTES_REASON}"),
            "the unmeasured phrase is the banner and the reason, nothing else",
        );
        let (banner, _reason) = rendered
            .split_once(" — ")
            .expect("banner, then the server's reason");
        assert!(
            !banner.contains(|c: char| c.is_ascii_digit()),
            "no number may stand where the byte figure would be: {banner:?}",
        );
    }

    #[test]
    fn partial_coverage_is_in_the_header_above_every_figure() {
        let s = summary(812, 634, FreedBytes::Exact { bytes: 12_345 }, "partial");
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        let coverage_at = out.find("PARTIAL").expect("partial is stated");
        let first_total = out.find("WHAT WOULD BE EXPIRED").expect("totals section");
        assert!(
            coverage_at < first_total,
            "partial coverage must precede the numbers it qualifies:\n{out}"
        );
    }

    #[test]
    fn rows_are_labelled_as_a_count_next_to_their_value() {
        let s = summary(
            51_535,
            34_102,
            FreedBytes::Exact { bytes: 4_096 },
            "complete",
        );
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        let line = out
            .lines()
            .find(|l| l.contains("51,535"))
            .expect("the row count appears");
        assert!(
            line.contains("a count, not a size"),
            "the row count must be labelled where it is printed: {line}"
        );
    }

    #[test]
    fn an_omitted_size_never_renders_as_zero_blank_or_dash() {
        let s = summary(
            10,
            10,
            FreedBytes::Omitted {
                reason: "refcount simulation was unavailable".into(),
            },
            "complete",
        );
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        let line = out
            .lines()
            .find(|l| l.contains("storage freed"))
            .expect("the storage line exists");
        assert!(line.contains("NOT MEASURED"), "{line}");
        assert!(line.contains("refcount simulation"), "{line}");
        assert!(!line.contains(" 0"), "a zero must not appear: {line}");
        assert!(!line.contains(" - "), "a dash must not appear: {line}");
    }

    #[test]
    fn repositories_are_named_by_key_not_uuid() {
        let s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        assert!(out.contains("npmproxy"), "the key is shown:\n{out}");
        assert!(
            !out.contains("11111111-0000-0000-0000"),
            "no repository UUID in human output:\n{out}"
        );
    }

    #[test]
    fn a_missing_key_is_labelled_rather_than_silently_shown_as_an_id() {
        let label = repository_label("", "11111111-2222-3333-4444-555555555555");
        assert!(label.contains("no key reported"), "{label}");
    }

    #[test]
    fn the_group_table_carries_no_byte_column() {
        let s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        let header = out
            .lines()
            .find(|l| l.contains("POLICY") && l.contains("ARTIFACT ROWS"))
            .expect("group header");
        assert!(!header.to_lowercase().contains("byte"), "{header}");
        assert!(
            out.contains("no byte column here"),
            "and it says why:\n{out}"
        );
    }

    #[test]
    fn the_sample_shows_name_version_and_age() {
        let s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        let out = render_preview("RETENTION PREVIEW", &facts(), &s, 20);
        assert!(out.contains("SAMPLE"), "{out}");
        assert!(out.contains("left-pad"), "{out}");
        assert!(out.contains("1.3.0"), "{out}");
        assert!(out.contains("1d 3h"), "age rendered: {out}");
    }

    #[test]
    fn a_deduplicated_job_says_it_is_not_a_fresh_observation() {
        let mut f = facts();
        f.deduplicated = true;
        let s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        let out = render_preview("RETENTION PREVIEW", &f, &s, 20);
        assert!(out.contains("not a fresh"), "{out}");
    }

    #[test]
    fn age_renders_days_hours_and_minutes() {
        assert_eq!(age(98_765), "1d 3h");
        assert_eq!(age(7_200), "2h");
        assert_eq!(age(600), "10m");
        assert_eq!(age(-1), "(future)");
    }

    #[test]
    fn identical_previews_produce_no_change() {
        let s = summary(10, 8, FreedBytes::Exact { bytes: 99 }, "complete");
        let d = diff(&s, &s);
        assert!(!d.changed());
        let rendered = render_delta(&d, "job-a", "job-b");
        assert!(rendered.starts_with("NOTHING CHANGED"), "{rendered}");
    }

    #[test]
    fn a_differing_preview_shows_every_moved_figure() {
        let before = summary(10, 8, FreedBytes::Exact { bytes: 99 }, "complete");
        let after = summary(25, 19, FreedBytes::Exact { bytes: 500 }, "partial");
        let d = diff(&before, &after);
        assert!(d.changed());
        let rendered = render_delta(&d, "job-a", "job-b");
        assert!(rendered.starts_with("WHAT CHANGED"), "{rendered}");
        assert!(rendered.contains("+15"), "row delta shown: {rendered}");
        assert!(rendered.contains("+11"), "distinct delta shown: {rendered}");
        assert!(rendered.contains("changed"), "{rendered}");
        assert!(
            rendered.contains("10 -> 25"),
            "per-group movement shown: {rendered}"
        );
    }

    #[test]
    fn a_group_appearing_or_disappearing_is_a_change() {
        let mut before = summary(10, 8, FreedBytes::Exact { bytes: 99 }, "complete");
        let mut after = before.clone();
        after
            .preview
            .as_mut()
            .expect("preview")
            .groups
            .push(group("pypi-30d", "pypiproxy", 3, 3));
        let d = diff(&before, &after);
        assert!(d.changed());
        assert!(render_delta(&d, "a", "b").contains("new: 3"));

        before.preview.as_mut().expect("preview").groups.clear();
        let d = diff(&after, &before);
        assert!(d.changed());
        let rendered = render_delta(&d, "a", "b");
        assert!(rendered.contains("gone (was"), "{rendered}");
    }

    #[test]
    fn one_byte_is_singular() {
        assert_eq!(measured_bytes(1), "1 byte (measured)");
        assert_eq!(bytes_cell(&FreedBytes::Exact { bytes: 1 }), "1 byte");
        assert_eq!(
            byte_change(
                &FreedBytes::Exact { bytes: 1 },
                &FreedBytes::Exact { bytes: 2 }
            ),
            "+1 byte"
        );
    }

    #[test]
    fn the_byte_change_is_a_number_only_when_both_sides_were_measured() {
        assert_eq!(
            byte_change(
                &FreedBytes::Exact { bytes: 100 },
                &FreedBytes::Exact { bytes: 140 }
            ),
            "+40 bytes"
        );
        assert_eq!(
            byte_change(
                &FreedBytes::Exact { bytes: 100 },
                &FreedBytes::Exact { bytes: 100 }
            ),
            "unchanged"
        );
        assert_eq!(
            byte_change(
                &FreedBytes::Exact { bytes: 100 },
                &FreedBytes::Omitted {
                    reason: "bound".into()
                }
            ),
            "no longer measured"
        );
        assert_eq!(
            byte_change(
                &FreedBytes::Omitted {
                    reason: "bound".into()
                },
                &FreedBytes::Exact { bytes: 100 }
            ),
            "now measured"
        );
        assert_eq!(
            byte_change(&FreedBytes::Unrecognised, &FreedBytes::Unrecognised),
            "unchanged"
        );
        assert_eq!(
            byte_change(
                &FreedBytes::Omitted { reason: "a".into() },
                &FreedBytes::Omitted { reason: "b".into() }
            ),
            "still not measured"
        );
    }

    #[test]
    fn a_partial_sweep_does_not_repeat_the_word_partial_back_at_the_operator() {
        let s = summary(1, 1, FreedBytes::Exact { bytes: 1 }, "partial");
        let out = render_preview("T", &facts(), &s, 0);
        assert!(out.contains("coverage    PARTIAL —"), "{out}");
    }

    #[test]
    fn an_unknown_coverage_word_is_quoted_verbatim() {
        let s = summary(1, 1, FreedBytes::Exact { bytes: 1 }, "truncated");
        let out = render_preview("T", &facts(), &s, 0);
        assert!(out.contains(r#"the server said "truncated""#), "{out}");
    }

    #[test]
    fn a_size_that_stops_being_measurable_is_a_change_not_a_zero() {
        let before = summary(10, 8, FreedBytes::Exact { bytes: 99 }, "complete");
        let after = summary(
            10,
            8,
            FreedBytes::Omitted {
                reason: OMITTED_BYTES_REASON.into(),
            },
            "complete",
        );
        let d = diff(&before, &after);
        assert!(d.changed(), "the byte status moved");
        let rendered = render_delta(&d, "a", "b");
        assert!(rendered.contains("not measured"), "{rendered}");
        assert!(rendered.contains(OMITTED_BYTES_REASON), "{rendered}");
    }

    #[test]
    fn diffing_against_a_summary_with_no_preview_still_shows_a_difference() {
        let empty = RetentionRunSummary {
            mode: "execute".into(),
            coverage: "complete".into(),
            ..RetentionRunSummary::default()
        };
        let real = summary(10, 8, FreedBytes::Exact { bytes: 99 }, "complete");
        let d = diff(&empty, &real);
        assert!(d.changed());
    }

    #[test]
    fn render_preview_on_a_summary_without_a_preview_says_so() {
        let s = RetentionRunSummary {
            mode: "execute".into(),
            coverage: "complete".into(),
            ..RetentionRunSummary::default()
        };
        let out = render_preview("T", &facts(), &s, 5);
        assert!(out.contains("no preview object"), "{out}");
    }

    #[test]
    fn empty_groups_and_sample_render_without_panicking() {
        let s = RetentionRunSummary {
            mode: "dry_run".into(),
            coverage: "complete".into(),
            preview: Some(PreviewBody::default()),
            ..RetentionRunSummary::default()
        };
        let out = render_preview("T", &facts(), &s, 5);
        assert!(out.contains("no policy matched anything"), "{out}");
        assert!(!out.contains("SAMPLE"), "{out}");
    }

    #[test]
    fn asking_for_no_sample_rows_prints_none() {
        let s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        let out = render_preview("T", &facts(), &s, 0);
        assert!(!out.contains("SAMPLE"), "{out}");
    }

    #[test]
    fn a_sample_row_whose_policy_is_missing_from_the_groups_is_still_rendered() {
        let mut s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        s.preview.as_mut().expect("preview").groups.clear();
        let out = render_preview("T", &facts(), &s, 5);
        assert!(out.contains("(unknown policy)"), "{out}");
    }

    #[test]
    fn a_sample_row_without_a_version_renders_a_placeholder() {
        let mut s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        s.preview.as_mut().expect("preview").sample[0].version = None;
        let out = render_preview("T", &facts(), &s, 5);
        assert!(out.contains("left-pad"), "{out}");
    }

    #[test]
    fn a_sample_at_the_server_cap_says_the_listing_is_capped() {
        let mut s = summary(5, 5, FreedBytes::Exact { bytes: 1 }, "complete");
        s.preview.as_mut().expect("preview").sample_limit = Some(1);
        let out = render_preview("T", &facts(), &s, 5);
        assert!(out.contains("records at most 1"), "{out}");
    }

    #[test]
    fn execution_result_reports_what_expired_and_that_bytes_are_a_later_stage() {
        let s = RetentionRunSummary {
            mode: "execute".into(),
            coverage: "complete".into(),
            policies: 2,
            evaluated: 400,
            expired: 17,
            ..RetentionRunSummary::default()
        };
        let out = render_execution(&facts(), &s);
        assert!(out.contains("RETENTION EXECUTED"), "{out}");
        assert!(out.contains("artifact rows expired now"), "{out}");
        assert!(out.contains("17"), "{out}");
        assert!(out.contains("does not itself delete stored bytes"), "{out}");
    }

    #[test]
    fn a_deduplicated_execution_says_the_confirmation_started_nothing() {
        let mut f = facts();
        f.deduplicated = true;
        let s = RetentionRunSummary {
            mode: "execute".into(),
            coverage: "complete".into(),
            ..RetentionRunSummary::default()
        };
        let out = render_execution(&f, &s);
        assert!(out.contains("no new sweep was started"), "{out}");
    }

    #[test]
    fn an_absent_coverage_word_is_reported_as_truncated_and_named() {
        let s = RetentionRunSummary {
            mode: "dry_run".into(),
            coverage: String::new(),
            preview: Some(PreviewBody::default()),
            ..RetentionRunSummary::default()
        };
        let out = render_preview("T", &facts(), &s, 0);
        assert!(out.contains("reported no coverage at all"), "{out}");
    }

    #[test]
    fn an_unreported_mode_is_labelled() {
        let s = RetentionRunSummary {
            coverage: "complete".into(),
            preview: Some(PreviewBody::default()),
            ..RetentionRunSummary::default()
        };
        let out = render_preview("T", &facts(), &s, 0);
        assert!(out.contains("(unreported)"), "{out}");
    }

    #[test]
    fn an_unreported_coverage_word_shows_as_unreported_in_the_delta() {
        let a = RetentionRunSummary::default();
        let b = RetentionRunSummary {
            coverage: "complete".into(),
            ..RetentionRunSummary::default()
        };
        let rendered = render_delta(&diff(&a, &b), "a", "b");
        assert!(rendered.contains("(unreported)"), "{rendered}");
    }
}
