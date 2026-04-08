//! Conversion helpers between Toasty string types and yauth domain types.

use chrono::NaiveDateTime;
use yauth::repo::RepoError;

/// Format for storing timestamps as strings in Toasty models.
const DT_FMT: &str = "%Y-%m-%dT%H:%M:%S%.f";

/// Convert a `NaiveDateTime` to an ISO 8601 string for Toasty storage.
pub(crate) fn dt_to_str(dt: NaiveDateTime) -> String {
    dt.format(DT_FMT).to_string()
}

/// Convert an `Option<NaiveDateTime>` to an optional string.
pub(crate) fn opt_dt_to_str(dt: Option<NaiveDateTime>) -> Option<String> {
    dt.map(dt_to_str)
}

/// Parse an ISO 8601 string back to `NaiveDateTime`.
pub(crate) fn str_to_dt(s: &str) -> NaiveDateTime {
    NaiveDateTime::parse_from_str(s, DT_FMT).unwrap_or_else(|e| {
        log::error!("Failed to parse datetime '{}': {}", s, e);
        chrono::Utc::now().naive_utc()
    })
}

/// Parse an optional string to `Option<NaiveDateTime>`.
pub(crate) fn opt_str_to_dt(s: Option<&str>) -> Option<NaiveDateTime> {
    s.map(str_to_dt)
}

/// Serialize `serde_json::Value` to string for Toasty storage.
pub(crate) fn json_to_str(v: &serde_json::Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "null".to_string())
}

/// Serialize `Option<serde_json::Value>` to optional string.
pub(crate) fn opt_json_to_str(v: Option<&serde_json::Value>) -> Option<String> {
    v.map(json_to_str)
}

/// Parse a string back to `serde_json::Value`.
pub(crate) fn str_to_json(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| {
        log::error!("Failed to parse JSON '{}': {}", s, e);
        serde_json::Value::Null
    })
}

/// Parse an optional string to `Option<serde_json::Value>`.
pub(crate) fn opt_str_to_json(s: Option<&str>) -> Option<serde_json::Value> {
    s.map(str_to_json)
}

/// Map a Toasty error to `RepoError::Internal`.
pub(crate) fn toasty_err(e: toasty::Error) -> RepoError {
    RepoError::Internal(format!("{e}").into())
}

/// Detect unique constraint violations and map to `RepoError::Conflict`.
pub(crate) fn toasty_conflict(e: toasty::Error) -> RepoError {
    let msg = format!("{e}");
    if msg.contains("duplicate key")
        || msg.contains("unique constraint")
        || msg.contains("UNIQUE constraint failed")
        || msg.contains("Duplicate entry")
    {
        return RepoError::Conflict(msg);
    }
    RepoError::Internal(msg.into())
}
