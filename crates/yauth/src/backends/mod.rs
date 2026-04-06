#[cfg(any(
    feature = "diesel-pg-backend",
    feature = "diesel-libsql-backend",
    feature = "diesel-mysql-backend",
    feature = "diesel-sqlite-backend"
))]
pub(crate) mod diesel_common;

#[cfg(feature = "diesel-pg-backend")]
pub mod diesel_pg;

#[cfg(feature = "diesel-libsql-backend")]
pub mod diesel_libsql;

#[cfg(feature = "diesel-mysql-backend")]
pub mod diesel_mysql;

#[cfg(feature = "diesel-sqlite-backend")]
pub mod diesel_sqlite;

#[cfg(feature = "memory-backend")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;
