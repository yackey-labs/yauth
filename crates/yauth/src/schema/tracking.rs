//! Schema tracking table — records applied schema hashes to make migrations idempotent.

use super::collector::YAuthSchema;

/// Compute a deterministic hash of the schema for tracking purposes.
///
/// The hash is based on a canonical text representation of all tables,
/// columns, types, constraints, and foreign keys — sorted deterministically.
/// Stable canonical string for a ColumnType — does NOT use derive(Debug) which
/// can change across compiler versions.
fn canonical_col_type(ct: &super::types::ColumnType) -> String {
    use super::types::ColumnType;
    match ct {
        ColumnType::Uuid => "Uuid".to_string(),
        ColumnType::Varchar => "Varchar".to_string(),
        ColumnType::VarcharN(n) => format!("VarcharN({n})"),
        ColumnType::Boolean => "Boolean".to_string(),
        ColumnType::DateTime => "DateTime".to_string(),
        ColumnType::Json => "Json".to_string(),
        ColumnType::Int => "Int".to_string(),
        ColumnType::SmallInt => "SmallInt".to_string(),
        ColumnType::Text => "Text".to_string(),
    }
}

fn canonical_on_delete(od: &super::types::OnDelete) -> &'static str {
    use super::types::OnDelete;
    match od {
        OnDelete::Cascade => "Cascade",
        OnDelete::SetNull => "SetNull",
        OnDelete::Restrict => "Restrict",
        OnDelete::NoAction => "NoAction",
    }
}

pub fn schema_hash(schema: &YAuthSchema) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    for table in &schema.tables {
        hasher.update(b"TABLE:");
        hasher.update(table.name.as_bytes());
        hasher.update(b"\n");

        for col in &table.columns {
            hasher.update(b"  COL:");
            hasher.update(col.name.as_bytes());
            hasher.update(b":");
            hasher.update(canonical_col_type(&col.col_type).as_bytes());
            hasher.update(b":");
            hasher.update(if col.nullable {
                b"NULL" as &[u8]
            } else {
                b"NOT_NULL"
            });
            hasher.update(b":");
            hasher.update(if col.primary_key { b"PK" as &[u8] } else { b"" });
            hasher.update(b":");
            hasher.update(if col.unique { b"UQ" as &[u8] } else { b"" });
            hasher.update(b":");
            if let Some(default) = col.default {
                hasher.update(b"DEFAULT=");
                hasher.update(default.as_bytes());
            }
            hasher.update(b":");
            if let Some(ref fk) = col.foreign_key {
                hasher.update(b"FK=");
                hasher.update(fk.references_table.as_bytes());
                hasher.update(b".");
                hasher.update(fk.references_column.as_bytes());
                hasher.update(b":");
                hasher.update(canonical_on_delete(&fk.on_delete).as_bytes());
            }
            hasher.update(b"\n");
        }

        // Include indices in hash so adding an index triggers re-migration
        for idx in &table.indices {
            hasher.update(b"  IDX:");
            hasher.update(idx.name.as_bytes());
            hasher.update(b":");
            for col_name in &idx.columns {
                hasher.update(col_name.as_bytes());
                hasher.update(b",");
            }
            hasher.update(if idx.unique { b"UQ" as &[u8] } else { b"" });
            hasher.update(b"\n");
        }
    }

    let result = hasher.finalize();
    hex::encode(result)
}

/// Ensure the `yauth_schema_migrations` tracking table exists.
#[cfg(feature = "diesel-backend")]
pub async fn ensure_tracking_table(
    conn: &mut diesel_async_crate::AsyncPgConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::RunQueryDsl;

    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS yauth_schema_migrations (\
            id SERIAL PRIMARY KEY, \
            schema_hash VARCHAR(64) NOT NULL, \
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
        )",
    )
    .execute(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(())
}

/// Check if the given schema hash has already been applied.
#[cfg(feature = "diesel-backend")]
pub async fn is_schema_applied(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    hash: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use diesel::QueryableByName;
    use diesel::sql_types::BigInt;
    use diesel_async_crate::RunQueryDsl;

    #[derive(QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    let rows: Vec<CountRow> = diesel::sql_query(
        "SELECT COUNT(*)::bigint AS count FROM yauth_schema_migrations WHERE schema_hash = $1",
    )
    .bind::<diesel::sql_types::Text, _>(hash)
    .load(conn)
    .await
    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(rows
        .into_iter()
        .next()
        .map(|r| r.count > 0)
        .unwrap_or(false))
}

/// Record that a schema hash has been applied.
#[cfg(feature = "diesel-backend")]
pub async fn record_schema_applied(
    conn: &mut diesel_async_crate::AsyncPgConnection,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_async_crate::RunQueryDsl;

    diesel::sql_query("INSERT INTO yauth_schema_migrations (schema_hash) VALUES ($1)")
        .bind::<diesel::sql_types::Text, _>(hash)
        .execute(conn)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    Ok(())
}
