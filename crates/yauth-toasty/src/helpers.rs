//! Conversion helpers between Toasty jiff types and yauth domain chrono types,
//! plus error mapping.

use chrono::NaiveDateTime;
use yauth::repo::RepoError;

// -- Timestamp bridging (jiff ↔ chrono) --

/// Lossless via epoch-seconds + subsec-nanos; falls back to Unix epoch on
/// out-of-range values.
pub(crate) fn jiff_to_chrono(ts: jiff::Timestamp) -> NaiveDateTime {
    chrono::DateTime::from_timestamp(ts.as_second(), ts.subsec_nanosecond() as u32)
        .map(|dt| dt.naive_utc())
        .unwrap_or(chrono::DateTime::UNIX_EPOCH.naive_utc())
}

pub(crate) fn opt_jiff_to_chrono(ts: Option<jiff::Timestamp>) -> Option<NaiveDateTime> {
    ts.map(jiff_to_chrono)
}

/// Lossless via epoch-seconds + subsec-nanos; falls back to `Timestamp::UNIX_EPOCH`
/// for values outside jiff's range.
pub(crate) fn chrono_to_jiff(dt: NaiveDateTime) -> jiff::Timestamp {
    let utc = dt.and_utc();
    jiff::Timestamp::new(utc.timestamp(), utc.timestamp_subsec_nanos() as i32)
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}

pub(crate) fn opt_chrono_to_jiff(dt: Option<NaiveDateTime>) -> Option<jiff::Timestamp> {
    dt.map(chrono_to_jiff)
}

// -- JSON bridging (typed Toasty fields ↔ serde_json::Value) --

/// Deserialize a domain `serde_json::Value` into a typed Toasty field.
///
/// Returns `T::default()` when the value is `null` or the wrong shape, which
/// matches the semantics of the old `unwrap_or_default()` calls but keeps the
/// conversion in one place.
pub(crate) fn json_from_domain<T: serde::de::DeserializeOwned + Default>(
    v: serde_json::Value,
) -> T {
    serde_json::from_value(v).unwrap_or_default()
}

/// Serialize a typed Toasty field back into a domain `serde_json::Value`.
pub(crate) fn json_to_domain<T: serde::Serialize>(v: T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or_default()
}

// -- Error mapping --

/// Check whether a Toasty error represents a "not found" condition.
///
/// Toasty 0.4 doesn't expose typed error variants; we match on the Display
/// output so this logic lives in one place and can be swapped when Toasty
/// adds structured errors.
pub(crate) fn is_not_found(e: &toasty::Error) -> bool {
    let msg = e.to_string();
    msg.contains("not found") || msg.contains("no rows")
}

pub(crate) fn toasty_err(e: toasty::Error) -> RepoError {
    RepoError::Internal(e.to_string().into())
}

/// Detect unique constraint violations and map to `RepoError::Conflict`.
pub(crate) fn toasty_conflict(e: toasty::Error) -> RepoError {
    let msg = e.to_string();
    if msg.contains("duplicate key")
        || msg.contains("unique constraint")
        || msg.contains("UNIQUE constraint failed")
        || msg.contains("Duplicate entry")
    {
        return RepoError::Conflict(msg);
    }
    RepoError::Internal(msg.into())
}
