//! Conversion helpers between Toasty jiff types and yauth domain chrono types,
//! plus error mapping.

use chrono::NaiveDateTime;
use yauth::repo::RepoError;

/// Convert `jiff::Timestamp` to `chrono::NaiveDateTime` for domain types.
///
/// Uses epoch-seconds + subsecond-nanoseconds as the bridge for lossless conversion.
/// Returns the Unix epoch on out-of-range timestamps (safe for round-tripping
/// through `chrono_to_jiff`).
pub(crate) fn jiff_to_chrono(ts: jiff::Timestamp) -> NaiveDateTime {
    let epoch_secs = ts.as_second();
    let nanos = ts.subsec_nanosecond();
    chrono::DateTime::from_timestamp(epoch_secs, nanos as u32)
        .map(|dt| dt.naive_utc())
        .unwrap_or(NaiveDateTime::UNIX_EPOCH)
}

/// Convert `Option<jiff::Timestamp>` to `Option<chrono::NaiveDateTime>`.
pub(crate) fn opt_jiff_to_chrono(ts: Option<jiff::Timestamp>) -> Option<NaiveDateTime> {
    ts.map(jiff_to_chrono)
}

/// Convert `chrono::NaiveDateTime` to `jiff::Timestamp` for Toasty entities.
///
/// Uses epoch-seconds + subsecond-nanoseconds as the bridge for lossless conversion.
/// Returns `jiff::Timestamp::UNIX_EPOCH` for values outside jiff's supported range
/// rather than panicking.
pub(crate) fn chrono_to_jiff(dt: NaiveDateTime) -> jiff::Timestamp {
    let utc = dt.and_utc();
    jiff::Timestamp::new(utc.timestamp(), utc.timestamp_subsec_nanos() as i32)
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
}

/// Convert `Option<chrono::NaiveDateTime>` to `Option<jiff::Timestamp>`.
pub(crate) fn opt_chrono_to_jiff(dt: Option<NaiveDateTime>) -> Option<jiff::Timestamp> {
    dt.map(chrono_to_jiff)
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
