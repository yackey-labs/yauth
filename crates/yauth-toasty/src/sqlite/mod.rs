//! Toasty-based SQLite backend for yauth.
//!
//! Experimental: Toasty is pre-1.0. API may change.

use toasty::Db;
use yauth::repo::{DatabaseBackend, RepoError, Repositories};

/// Experimental: Toasty-based SQLite backend.
#[doc = "Experimental: Toasty is pre-1.0. API may change."]
pub struct ToastySqliteBackend {
    db: Db,
}

impl ToastySqliteBackend {
    /// Connect to SQLite using a URL (e.g., `sqlite::memory:` or `sqlite://path`).
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let db = Self::build_db(url)
            .await
            .map_err(|e| RepoError::Internal(format!("toasty sqlite connect error: {e}").into()))?;
        Ok(Self { db })
    }

    async fn build_db(url: &str) -> toasty::Result<Db> {
        let mut builder = Db::builder();
        builder
            .table_name_prefix("yauth_")
            .models(Self::all_models());
        builder.connect(url).await
    }

    /// Wrap an existing Toasty `Db` as a yauth backend.
    ///
    /// Use this when your app registers additional Toasty models (e.g., a
    /// `Todo` model) alongside yauth's models in the same `Db`:
    ///
    /// ```ignore
    /// let db = toasty::Db::builder()
    ///     .table_name_prefix("yauth_")
    ///     .models(toasty::models!(crate::*, yauth_toasty::*))
    ///     .connect("sqlite://app.db")
    ///     .await?;
    ///
    /// let backend = ToastySqliteBackend::from_db(db);
    /// ```
    pub fn from_db(db: Db) -> Self {
        Self { db }
    }

    /// Get a reference to the underlying Toasty `Db`.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Create all tables using `push_schema()`.
    pub async fn create_tables(&self) -> Result<(), RepoError> {
        self.db
            .push_schema()
            .await
            .map_err(|e| RepoError::Internal(format!("push_schema error: {e}").into()))
    }

    fn all_models() -> toasty::schema::app::ModelSet {
        toasty::models!(crate::*)
    }
}

impl DatabaseBackend for ToastySqliteBackend {
    fn repositories(&self) -> Repositories {
        crate::common::build_repositories(&self.db)
    }
}
