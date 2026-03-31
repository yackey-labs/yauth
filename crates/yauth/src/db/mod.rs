pub mod migrations;
pub mod models;
pub mod schema;

use diesel::prelude::*;
use diesel::result::OptionalExtension;
use diesel_async_crate::RunQueryDsl;
use uuid::Uuid;

/// Connection type alias shared across all plugins.
pub type Conn = diesel_async_crate::AsyncPgConnection;

/// Result type alias for database helpers that map errors to `String`.
pub type DbResult<T> = Result<T, String>;

pub async fn find_user_by_id(conn: &mut Conn, id: Uuid) -> DbResult<Option<models::User>> {
    use schema::yauth_users;
    yauth_users::table
        .find(id)
        .select(models::User::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}

pub async fn find_user_by_email(conn: &mut Conn, email: &str) -> DbResult<Option<models::User>> {
    use schema::yauth_users;
    yauth_users::table
        .filter(yauth_users::email.eq(email))
        .select(models::User::as_select())
        .first(conn)
        .await
        .optional()
        .map_err(|e| e.to_string())
}
