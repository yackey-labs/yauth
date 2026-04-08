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

#[cfg(any(
    feature = "seaorm-pg-backend",
    feature = "seaorm-mysql-backend",
    feature = "seaorm-sqlite-backend"
))]
#[allow(dead_code)]
pub(crate) mod seaorm_common;

#[cfg(feature = "seaorm-pg-backend")]
pub mod seaorm_pg;

#[cfg(feature = "seaorm-mysql-backend")]
pub mod seaorm_mysql;

#[cfg(feature = "seaorm-sqlite-backend")]
pub mod seaorm_sqlite;

#[cfg(feature = "memory-backend")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;
