//! Output formatting helpers for `hort-cli`.
//!
//! Two modes: pretty-printed JSON (for `--output json`) and an aligned
//! column table (for `--output table`). No extra crate dependencies —
//! the table renderer is intentionally minimal: column-width alignment,
//! space-padded, no unicode borders.

/// Serialise `v` to a pretty-printed JSON string.
///
/// Used by commands that respect `--output json`.
pub fn format_json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v)
        .unwrap_or_else(|e| format!("{{\"error\":\"serialise failed: {e}\"}}"))
}

/// Render `rows` as an aligned-column text table with `headers` in the
/// first row.
///
/// Column widths are computed as `max(header_len, max(cell_len for col))`.
/// Each column is left-padded to that width and separated by two spaces.
/// An empty `rows` list still renders the header row (useful for `list`
/// commands that return no results).
///
/// # Example
///
/// ```
/// use hort_cli::output::format_table_rows;
/// let rows = vec![vec!["my-repo".to_string(), "active".to_string()]];
/// let out = format_table_rows(&["NAME", "STATUS"], &rows);
/// assert!(out.starts_with("NAME"));
/// assert!(out.contains("my-repo"));
/// ```
pub fn format_table_rows(headers: &[&str], rows: &[Vec<String>]) -> String {
    // Compute column widths.
    let n_cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();

    for row in rows {
        for (i, cell) in row.iter().enumerate().take(n_cols) {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let separator = "  "; // two spaces between columns
    let mut out = String::new();

    // Header row.
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<width$}", h, width = widths[i]))
        .collect();
    out.push_str(&header_line.join(separator));
    out.push('\n');

    // Data rows.
    for row in rows {
        let padded: Vec<String> = widths
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                let cell = row.get(i).map(String::as_str).unwrap_or("");
                format!("{cell:<w$}")
            })
            .collect();
        out.push_str(&padded.join(separator));
        out.push('\n');
    }

    out
}

// -----------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        name: String,
        count: u32,
    }

    // Test 7: format_json round-trip.
    #[test]
    fn format_json_round_trip() {
        let v = Sample {
            name: "my-repo".to_string(),
            count: 42,
        };
        let s = format_json(&v);
        let parsed: serde_json::Value = serde_json::from_str(&s).expect("valid json");
        assert_eq!(parsed["name"], "my-repo");
        assert_eq!(parsed["count"], 42);
        // Pretty-printed — should contain newlines.
        assert!(s.contains('\n'), "expected pretty-printed newlines");
    }

    // Test 8: format_table_rows column alignment.
    #[test]
    fn format_table_rows_alignment() {
        let headers = &["NAME", "STATUS", "COUNT"];
        let rows = vec![
            vec!["short".to_string(), "active".to_string(), "1".to_string()],
            vec![
                "a-much-longer-name".to_string(),
                "inactive".to_string(),
                "1234".to_string(),
            ],
        ];
        let out = format_table_rows(headers, &rows);
        let lines: Vec<&str> = out.lines().collect();

        // Header row present.
        assert_eq!(lines.len(), 3, "header + 2 data rows");
        assert!(lines[0].starts_with("NAME"), "header starts with NAME");

        // All lines should have the same width (because the last column is
        // padded to equal width too — trim trailing spaces and just check
        // relative structure).
        // The longest NAME is "a-much-longer-name" (18 chars) vs "NAME" (4 chars).
        // So column 0 width == 18.
        assert!(
            lines[0].starts_with("NAME              "),
            "header NAME padded to 18: {:?}",
            lines[0]
        );
        assert!(
            lines[2].starts_with("a-much-longer-name"),
            "data row not padded beyond its content: {:?}",
            lines[2]
        );
    }

    #[test]
    fn format_table_rows_empty_data_renders_header() {
        let out = format_table_rows(&["ID", "NAME"], &[]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("ID"));
    }
}
