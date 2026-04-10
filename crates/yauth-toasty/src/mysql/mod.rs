//! Toasty-based MySQL backend for yauth (experimental support).

use toasty::Db;
use yauth::repo::{DatabaseBackend, RepoError, Repositories};

/// Toasty-based MySQL backend (experimental support).
pub struct ToastyMysqlBackend {
    db: Db,
}

impl ToastyMysqlBackend {
    /// Connect to MySQL using a URL.
    pub async fn new(url: &str) -> Result<Self, RepoError> {
        let db = Self::build_db(url)
            .await
            .map_err(|e| RepoError::Internal(format!("toasty mysql connect error: {e}").into()))?;
        Ok(Self { db })
    }

    async fn build_db(url: &str) -> toasty::Result<Db> {
        let mut builder = Db::builder();
        builder
            .table_name_prefix("yauth_")
            .models(Self::all_models());
        builder.connect(url).await
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

impl DatabaseBackend for ToastyMysqlBackend {
    fn repositories(&self) -> Repositories {
        crate::common::build_repositories(&self.db)
    }
}
