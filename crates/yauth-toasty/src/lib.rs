//! Toasty ORM backends for yauth (experimental).
//!
//! This crate provides Toasty-based database backends for the yauth
//! authentication library. It lives in a separate crate because Toasty's
//! SQLite driver uses a different `libsqlite3-sys` version than sqlx,
//! causing a Cargo `links` conflict if both are in the same crate.
//!
//! # Usage
//!
//! ```toml
//! yauth = { version = "0.8", features = ["full"] }
//! yauth-toasty = { git = "https://github.com/yackey-labs/yauth", features = ["postgresql"] }
//! ```
//!
//! # Features
//!
//! - `postgresql` — PostgreSQL backend via `toasty-driver-postgresql`
//! - `mysql` — MySQL backend via `toasty-driver-mysql`
//! - `sqlite` — SQLite backend via `toasty-driver-sqlite`
//!
//! **Warning:** Toasty is pre-1.0. Expect breaking changes across 0.x releases.

#![doc = "Experimental: Toasty is pre-1.0. API may change."]

/// Shared Toasty entity definitions used by all backends.
pub mod entities;

/// Shared conversion helpers (datetime, JSON, UUID, error mapping).
#[allow(dead_code)]
pub(crate) mod helpers;

#[cfg(feature = "postgresql")]
pub mod pg;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub mod sqlite;
