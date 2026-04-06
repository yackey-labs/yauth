//! ORM-agnostic domain types — re-exported from `yauth-entity`.
//!
//! All domain types live in the `yauth-entity` crate.
//! This module re-exports them for internal use within the `yauth` crate.
//! External consumers should depend on `yauth-entity` directly.

pub use yauth_entity::*;
