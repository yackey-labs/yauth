//! Toasty ORM backends for yauth (experimental support).
//!
//! This crate provides Toasty-based database backends for the yauth
//! authentication library. It lives in a separate crate because Toasty's
//! SQLite driver uses a different `libsqlite3-sys` version than sqlx,
//! causing a Cargo `links` conflict if both are in the same crate.
//!
//! # Usage
//!
//! ```toml
//! yauth = { version = "0.9", default-features = false }
//! yauth-toasty = { git = "https://github.com/yackey-labs/yauth", features = ["sqlite", "email-password"] }
//! ```
//!
//! **Important:** Enable plugin features (e.g., `email-password`) on `yauth-toasty`,
//! not on `yauth` directly.
//!
//! # Features
//!
//! - `postgresql` — PostgreSQL backend via `toasty-driver-postgresql`
//! - `mysql` — MySQL backend via `toasty-driver-mysql`
//! - `sqlite` — SQLite backend via `toasty-driver-sqlite`

/// Shared Toasty entity definitions used by all backends.
pub mod entities;

/// Shared conversion helpers (datetime, JSON, UUID, error mapping).
#[allow(dead_code)]
pub(crate) mod helpers;

/// Shared repository implementations (dialect-agnostic).
pub(crate) mod common;

#[cfg(feature = "postgresql")]
pub mod pg;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub mod sqlite;
