//! Toasty-based PostgreSQL backend for yauth.
//!
//! Experimental: Toasty is pre-1.0. API may change.

use std::future::Future;
use std::pin::Pin;

use toasty::Db;
use yauth::repo::{DatabaseBackend, EnabledFeatures, RepoError, Repositories};

/// Experimental: Toasty-based PostgreSQL backend.
#[doc = "Experimental: Toasty is pre-1.0. API may change."]
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
            .models(Self::all_models());
        builder.connect(url).await
    }

    /// Get a reference to the underlying Toasty `Db`.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Create all tables using `push_schema()`.
    /// Intended for test setup — not for production use.
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

impl DatabaseBackend for ToastyPgBackend {
    fn migrate(
        &self,
        _features: &EnabledFeatures,
    ) -> Pin<Box<dyn Future<Output = Result<(), RepoError>> + Send + '_>> {
        // PG: best-effort schema validation (Toasty manages schema via push_schema)
        Box::pin(async move { Ok(()) })
    }

    fn repositories(&self) -> Repositories {
        crate::common::build_repositories(&self.db)
    }
}
