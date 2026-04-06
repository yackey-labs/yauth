//! Runtime Postgres migration diff -- requires a live diesel connection.
//!
//! This introspects the database via `information_schema` and produces
//! ALTER TABLE statements for new columns (additive only).

use yauth_migration::{ColumnType, YAuthSchema};

use std::borrow::Cow;

/// Map abstract column type to Postgres type string.
fn pg_type(col_type: &ColumnType) -> Cow<'static, str> {
    match col_type {
        ColumnType::Uuid => Cow::Borrowed("UUID"),
        ColumnType::Varchar => Cow::Borrowed("VARCHAR"),
        ColumnType::VarcharN(n) => Cow::Owned(format!("VARCHAR({n})")),
        ColumnType::Boolean => Cow::Borrowed("BOOLEAN"),
        ColumnType::DateTime => Cow::Borrowed("TIMESTAMPTZ"),
        ColumnType::Json => Cow::Borrowed("JSONB"),
        ColumnType::Int => Cow::Borrowed("INT"),
        ColumnType::SmallInt => Cow::Borrowed("SMALLINT"),
        ColumnType::Text => Cow::Borrowed("TEXT"),
    }
}

/// Introspect existing tables via information_schema and generate ALTER TABLE
/// statements for new columns (additive only).
///
/// Returns a list of SQL statements to execute.
#[cfg(feature = "diesel-pg-backend")]
pub async fn generate_migration_diff(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    schema_name: &str,
    target_schema: &YAuthSchema,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::QueryableByName;
    use diesel::sql_types::Text;
    use diesel_async_crate::RunQueryDsl;

    #[derive(QueryableByName)]
    struct ColumnInfo {
        #[diesel(sql_type = Text)]
        table_name: String,
        #[diesel(sql_type = Text)]
        column_name: String,
    }

    // Get all existing columns for yauth_ tables
    let existing: Vec<ColumnInfo> = diesel::sql_query(
        "SELECT table_name, column_name \
         FROM information_schema.columns \
         WHERE table_schema = $1 \
           AND table_name LIKE 'yauth_%' \
         ORDER BY table_name, ordinal_position",
    )
    .bind::<diesel::sql_types::Text, _>(schema_name)
    .load(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Build a set of (table_name, column_name) for fast lookup
    let existing_cols: std::collections::HashSet<(String, String)> = existing
        .into_iter()
        .map(|c| (c.table_name, c.column_name))
        .collect();

    let mut alter_statements = Vec::new();

    for table in &target_schema.tables {
        let table_exists = existing_cols.iter().any(|(t, _)| t == &table.name);

        if !table_exists {
            continue;
        }

        for col in &table.columns {
            let key = (table.name.clone(), col.name.clone());
            if !existing_cols.contains(&key) {
                let mut stmt = format!(
                    "ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} {}",
                    table.name,
                    col.name,
                    &pg_type(&col.col_type),
                );

                if !col.nullable && col.default.is_none() {
                    stmt.push_str(" NULL");
                } else {
                    if !col.nullable {
                        stmt.push_str(" NOT NULL");
                    }
                    if let Some(ref default) = col.default {
                        stmt.push_str(&format!(" DEFAULT {}", default));
                    }
                }

                alter_statements.push(stmt);
            }
        }
    }

    Ok(alter_statements)
}
