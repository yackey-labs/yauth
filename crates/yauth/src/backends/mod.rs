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

#[cfg(any(
    feature = "sqlx-pg-backend",
    feature = "sqlx-mysql-backend",
    feature = "sqlx-sqlite-backend"
))]
pub(crate) mod sqlx_common;

#[cfg(feature = "sqlx-pg-backend")]
pub mod sqlx_pg;

#[cfg(feature = "sqlx-mysql-backend")]
pub mod sqlx_mysql;

#[cfg(feature = "sqlx-sqlite-backend")]
pub mod sqlx_sqlite;

#[cfg(feature = "memory-backend")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;
