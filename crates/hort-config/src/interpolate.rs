//! `${ENV_VAR}` interpolation helper.
//!
//! Every per-kind parser that accepts string-typed fields routes them
//! through `interpolate` so the operator-facing schema has one
//! consistent escape-and-substitute story rather than per-field rules.
//!
//! Syntax:
//! - `${VAR}` substitutes from `std::env::var`.
//! - `$$` emits a literal `$` (so an operator can write a literal `$`
//!   in storage paths or upstream URLs without it being mistaken for
//!   the start of an interpolation).
//! - Anything else starting with `$` (`$VAR`, `${VAR` without a close,
//!   `${`) is malformed — the parser surfaces a concrete error.

use crate::error::ParseError;

/// Substitute `${VAR}` references in `input` against the process
/// environment.
///
/// The implementation walks the string once; it does not allocate when
/// no substitutions are needed (returns the input as a `String`). It
/// is safe to call from per-field parsers: the cost is linear in input
/// length and the only allocations are for the substituted values.
pub fn interpolate(input: &str) -> Result<String, ParseError> {
    interpolate_with(input, |var| std::env::var(var).ok())
}

/// Test seam — same algorithm, but the env lookup is provided by the
/// caller. Public-crate-internal so unit tests can exercise every
/// branch without `set_var`/`remove_var` ordering hazards (which can
/// poison adjacent tests under cargo's parallel runner).
pub(crate) fn interpolate_with<F>(input: &str, lookup: F) -> Result<String, ParseError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(input.len());
    let mut chars = input.char_indices().peekable();

    while let Some((i, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }

        // `$` reached. Inspect the next character to decide between
        // `$$` escape, `${VAR}` substitution, and malformed input.
        match chars.peek().copied() {
            // `$$` — emit a literal `$` and consume the second `$`.
            Some((_, '$')) => {
                out.push('$');
                chars.next();
            }
            // `${...}` — find the closing brace and look up the var.
            Some((open_i, '{')) => {
                // Consume the `{`.
                chars.next();
                // Slice from after the brace until the matching `}`.
                // Take the rest of the input and search for `}`.
                let after_brace = &input[open_i + 1..];
                let close_rel = after_brace.find('}').ok_or_else(|| {
                    ParseError::InterpolationMalformed {
                        // Show the offending fragment from `$` to EOL
                        // (or end of input) so the operator can find
                        // it in their YAML.
                        fragment: input[i..].to_string(),
                    }
                })?;
                let var = &after_brace[..close_rel];
                if var.is_empty() {
                    return Err(ParseError::InterpolationMalformed {
                        fragment: "${}".into(),
                    });
                }
                let value = lookup(var).ok_or_else(|| ParseError::InterpolationVarNotFound {
                    var: var.to_string(),
                })?;
                out.push_str(&value);
                // Advance the iterator past the closing brace + the
                // var name we just consumed. The peekable iterator
                // doesn't expose seek, so re-prime by skipping the
                // right number of characters.
                let consumed = var.chars().count() + 1; // +1 for `}`
                for _ in 0..consumed {
                    chars.next();
                }
            }
            // Anything else after `$` is malformed (`$VAR`, lone `$`).
            _ => {
                return Err(ParseError::InterpolationMalformed {
                    fragment: input[i..].to_string(),
                });
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup_table(entries: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: std::collections::HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |var| owned.get(var).cloned()
    }

    #[test]
    fn no_interpolation_returns_input_verbatim() {
        let out = interpolate_with("/var/lib/hort/repo", |_| None).unwrap();
        assert_eq!(out, "/var/lib/hort/repo");
    }

    #[test]
    fn bare_substitution() {
        let lookup = lookup_table(&[("HOME", "/home/op")]);
        let out = interpolate_with("${HOME}", lookup).unwrap();
        assert_eq!(out, "/home/op");
    }

    #[test]
    fn embedded_substitution_in_longer_string() {
        let lookup = lookup_table(&[("VAR", "middle")]);
        let out = interpolate_with("prefix_${VAR}_suffix", lookup).unwrap();
        assert_eq!(out, "prefix_middle_suffix");
    }

    #[test]
    fn multiple_substitutions_in_one_pass() {
        let lookup = lookup_table(&[("A", "apple"), ("B", "banana")]);
        let out = interpolate_with("${A} and ${B}", lookup).unwrap();
        assert_eq!(out, "apple and banana");
    }

    #[test]
    fn escape_double_dollar_emits_literal() {
        let out = interpolate_with("price: $$5", |_| None).unwrap();
        assert_eq!(out, "price: $5");
    }

    #[test]
    fn missing_var_is_concrete_error() {
        let err = interpolate_with("${MISSING}", |_| None).unwrap_err();
        match err {
            ParseError::InterpolationVarNotFound { var } => assert_eq!(var, "MISSING"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn malformed_unclosed_brace() {
        let err = interpolate_with("prefix_${VAR_no_close", |_| None).unwrap_err();
        match err {
            ParseError::InterpolationMalformed { fragment } => {
                assert!(fragment.contains("${VAR_no_close"))
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn malformed_lone_dollar() {
        let err = interpolate_with("${} empty", |_| None).unwrap_err();
        assert!(matches!(err, ParseError::InterpolationMalformed { .. }));
    }

    #[test]
    fn malformed_dollar_without_brace_or_dollar() {
        // `$VAR` is not the supported syntax — only `${VAR}`. Treat it
        // as malformed so a stray `$` typo doesn't silently become
        // part of the path.
        let err = interpolate_with("$VAR", |_| None).unwrap_err();
        assert!(matches!(err, ParseError::InterpolationMalformed { .. }));
    }

    #[test]
    fn lone_trailing_dollar_is_malformed() {
        let err = interpolate_with("trailing$", |_| None).unwrap_err();
        assert!(matches!(err, ParseError::InterpolationMalformed { .. }));
    }

    #[test]
    fn double_dollar_at_end_of_string() {
        let out = interpolate_with("end$$", |_| None).unwrap();
        assert_eq!(out, "end$");
    }

    #[test]
    fn substitution_followed_by_more_text_advances_correctly() {
        // Regression for off-by-one in the consume-after-close-brace
        // logic. If the iterator skips one too many chars, the `_tail`
        // suffix gets corrupted; one too few leaves a stray `}`.
        let lookup = lookup_table(&[("X", "ABC")]);
        let out = interpolate_with("${X}_tail", lookup).unwrap();
        assert_eq!(out, "ABC_tail");
    }

    #[test]
    fn interpolate_public_api_works_against_real_env() {
        // Use a var name unlikely to be set in CI; assert the missing
        // case surfaces. We do NOT call `set_var` here — that would
        // race with adjacent tests under cargo's parallel runner.
        let err = interpolate("${HORT_INTERPOLATE_TEST_NEVER_SET_VAR_zzz}").unwrap_err();
        assert!(matches!(err, ParseError::InterpolationVarNotFound { .. }));
    }
}
