//! Schema hash computation for tracking purposes.

use super::collector::YAuthSchema;
use super::types::{ColumnType, OnDelete};

/// Stable canonical string for a ColumnType.
fn canonical_col_type(ct: &ColumnType) -> String {
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

fn canonical_on_delete(od: &OnDelete) -> &'static str {
    match od {
        OnDelete::Cascade => "Cascade",
        OnDelete::SetNull => "SetNull",
        OnDelete::Restrict => "Restrict",
        OnDelete::NoAction => "NoAction",
    }
}

/// Compute a deterministic hash of the schema for tracking purposes.
///
/// The hash is based on a canonical text representation of all tables,
/// columns, types, constraints, and foreign keys -- sorted deterministically.
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
            if let Some(ref default) = col.default {
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
