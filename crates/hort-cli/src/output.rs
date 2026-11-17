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

/// The widest a column is ever padded to.
///
/// Two reasons for a bound, one hard and one the reason this number and
/// not a larger one:
///
/// - `std::fmt` packs a field width into 16 bits, so formatting with a
///   width of 65536 or more panics at runtime with "Formatting argument
///   out of range". The width comes from cell length, i.e. from whatever
///   the server returned, so an uncapped width makes the renderer
///   crashable by its own input.
/// - Padding exists to align columns on a terminal, and no terminal
///   displays a 512-character line as a readable table row — a cell that
///   wide already wraps wherever it is shown. Past that width the pad
///   aligns nothing while costing every *other* cell in the column the
///   same run of spaces, which is how one large value turns a two-column
///   table into tens of thousands of blanks per row.
const MAX_PAD_WIDTH: usize = 512;

/// Render `rows` as an aligned-column text table with `headers` in the
/// first row.
///
/// Column widths are `min(MAX_PAD_WIDTH, max(header_len, max(cell_len for
/// col)))`. Each column is left-padded to that width and separated by two
/// spaces. An empty `rows` list still renders the header row (useful for
/// `list` commands that return no results).
///
/// **Padding never truncates, and the cap changes no cell.** A cell longer
/// than its column's pad width is emitted whole and simply runs past the
/// column, so the table shows every byte it was given at any input size;
/// what the cap bounds is the number of spaces a short cell is padded with
/// and whether the renderer can be made to panic.
///
/// Widths are measured in bytes, so a multi-byte cell aligns loosely.
/// That predates the cap and is unchanged by it.
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
    // Compute column widths, capped — see `MAX_PAD_WIDTH`.
    let n_cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len().min(MAX_PAD_WIDTH)).collect();

    for row in rows {
        for (i, cell) in row.iter().enumerate().take(n_cols) {
            widths[i] = widths[i].max(cell.len().min(MAX_PAD_WIDTH));
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

    /// `std::fmt` packs a field width into 16 bits: a width of 65536 or
    /// more is a runtime panic. The pad width comes from cell length, so
    /// both sides of that boundary must render — and must render the cell
    /// whole, since the cap bounds padding and not content.
    #[test]
    fn a_cell_either_side_of_the_fmt_width_boundary_renders_whole() {
        for len in [65_535_usize, 65_536] {
            let huge = "x".repeat(len);
            let out = format_table_rows(
                &["FIELD", "VALUE"],
                &[vec!["result_summary".to_string(), huge.clone()]],
            );
            assert!(
                out.contains(&huge),
                "a {len}-byte cell is emitted whole, never truncated by the pad",
            );
        }
    }

    /// The header row is rendered before any data row, so a huge *header*
    /// is the first width the formatter sees.
    #[test]
    fn a_huge_header_renders_too() {
        let huge = "H".repeat(70_000);
        let out = format_table_rows(&[huge.as_str(), "VALUE"], &[]);
        assert!(out.contains(&huge), "the header is emitted whole");
    }

    /// The pathology that exists below the panic threshold: the width is
    /// per *column*, so without a cap one huge cell pads every one of its
    /// column mates out to that same width in spaces.
    ///
    /// Asserted as a property rather than against `MAX_PAD_WIDTH`, so the
    /// cap stays a choice and not a second specification: past the cap the
    /// short row stops growing with the huge cell at all, so doubling the
    /// huge cell changes nothing about the row beside it.
    #[test]
    fn a_short_cell_is_not_padded_out_to_the_width_of_a_huge_one() {
        let short_row_len = |huge_len: usize| -> usize {
            let out = format_table_rows(
                &["FIELD", "VALUE"],
                &[
                    vec!["result_summary".to_string(), "x".repeat(huge_len)],
                    vec!["status".to_string(), "completed".to_string()],
                ],
            );
            out.lines()
                .find(|l| l.contains("completed"))
                .expect("the short row renders")
                .len()
        };

        assert_eq!(
            short_row_len(70_000),
            short_row_len(140_000),
            "a column mate's width must not scale with the huge cell",
        );
        assert!(
            short_row_len(70_000) < 70_000 / 10,
            "the short row stays an order of magnitude below the huge cell, got {}",
            short_row_len(70_000),
        );
    }
}
