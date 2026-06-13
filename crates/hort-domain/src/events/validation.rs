use crate::error::{DomainError, DomainResult};

pub(super) fn validate_string(field: &str, value: &str, max: usize) -> DomainResult<()> {
    if value.is_empty() {
        return Err(DomainError::Validation(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > max {
        Err(DomainError::Validation(format!(
            "{field} exceeds maximum length of {max} (got {})",
            value.len()
        )))
    } else {
        Ok(())
    }
}

pub(super) fn validate_optional_string(
    field: &str,
    value: &Option<String>,
    max: usize,
) -> DomainResult<()> {
    if let Some(v) = value {
        validate_string(field, v, max)
    } else {
        Ok(())
    }
}

pub(super) fn validate_json(
    field: &str,
    value: &serde_json::Value,
    max_size: usize,
    max_depth: usize,
) -> DomainResult<()> {
    let serialised = serde_json::to_string(value)
        .map_err(|e| DomainError::Validation(format!("{field} cannot be serialised: {e}")))?;
    if serialised.len() > max_size {
        return Err(DomainError::Validation(format!(
            "{field} exceeds maximum serialised size of {max_size} bytes (got {} bytes)",
            serialised.len()
        )));
    }
    let depth = json_depth(value);
    if depth > max_depth {
        return Err(DomainError::Validation(format!(
            "{field} exceeds maximum nesting depth of {max_depth} (got {depth})"
        )));
    }
    Ok(())
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(obj) => 1 + obj.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}
