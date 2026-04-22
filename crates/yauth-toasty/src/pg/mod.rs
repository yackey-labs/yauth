//! Toasty-based PostgreSQL backend for yauth (experimental support).

use toasty::Db;
use yauth::repo::{DatabaseBackend, RepoError, Repositories};

/// Toasty-based PostgreSQL backend (experimental support).
pub struct ToastyPgBackend {
    db: Db,
}

impl ToastyPgBackend {
    /// Connect to PostgreSQL using a URL.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let db = Self::build_db(url)
            .await
            .map_err(|e| RepoError::Internal(format!("toasty connect error: {e}").into()))?;
        Ok(Self { db })
    }

    async fn build_db(url: &str) -> toasty::Result<Db> {
        let mut builder = Db::builder();
        builder
            .table_name_prefix("yauth_")
            // NOTE: Inside yauth-toasty we use `toasty::models!(crate::*)`
            // directly — it resolves via `env!("CARGO_PKG_NAME")`. External
            // consumers should call [`crate::all_models!`] instead.
            .models(toasty::models!(crate::*));
        builder.connect(url).await
    }

    /// Get a reference to the underlying Toasty `Db`.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Create all tables using `push_schema()`.
    ///
    /// **For tests only.** This drops and recreates tables without tracking.
    /// For production, use [`yauth_toasty::apply_migrations(&db)`](crate::apply_migrations)
    /// instead, which provides tracked, checksummed, incremental migrations.
    pub async fn create_tables(&self) -> Result<(), RepoError> {
        self.db
            .push_schema()
            .await
            .map_err(|e| RepoError::Internal(format!("push_schema error: {e}").into()))
    }
}

impl DatabaseBackend for ToastyPgBackend {
    fn repositories(&self) -> Repositories {
        crate::common::build_repositories(&self.db)
    }
}
