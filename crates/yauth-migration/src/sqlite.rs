//! SQLite DDL generation.
//!
//! Maps abstract column types to SQLite-compatible types:
//! - UUID -> TEXT
//! - VARCHAR / VarcharN(n) -> TEXT (SQLite has no VARCHAR length limits)
//! - BOOLEAN -> INTEGER
//! - DateTime -> TEXT (ISO 8601 strings)
//! - Json -> TEXT
//! - INT -> INTEGER
//! - SMALLINT -> INTEGER
//! - TEXT -> TEXT

use std::borrow::Cow;

use super::collector::YAuthSchema;
use super::types::*;

/// Map abstract column type to SQLite type string.
pub(crate) fn sqlite_type(col_type: &ColumnType) -> Cow<'static, str> {
    match col_type {
        ColumnType::Uuid => Cow::Borrowed("TEXT"),
        ColumnType::Varchar => Cow::Borrowed("TEXT"),
        ColumnType::VarcharN(_) => Cow::Borrowed("TEXT"),
        ColumnType::Boolean => Cow::Borrowed("INTEGER"),
        ColumnType::DateTime => Cow::Borrowed("TEXT"),
        ColumnType::Json => Cow::Borrowed("TEXT"),
        ColumnType::Int => Cow::Borrowed("INTEGER"),
        ColumnType::SmallInt => Cow::Borrowed("INTEGER"),
        ColumnType::Text => Cow::Borrowed("TEXT"),
    }
}

/// Map OnDelete action to SQLite clause.
fn sqlite_on_delete(action: &OnDelete) -> &'static str {
    match action {
        OnDelete::Cascade => "ON DELETE CASCADE",
        OnDelete::SetNull => "ON DELETE SET NULL",
        OnDelete::Restrict => "ON DELETE RESTRICT",
        OnDelete::NoAction => "ON DELETE NO ACTION",
    }
}

/// Map a Postgres default expression to its SQLite equivalent.
pub(crate) fn sqlite_default(pg_default: &str) -> Option<Cow<'static, str>> {
    match pg_default {
        "gen_random_uuid()" => None,
        "now()" => Some(Cow::Borrowed("CURRENT_TIMESTAMP")),
        other => Some(Cow::Owned(other.to_string())),
    }
}

/// Generate a CREATE TABLE IF NOT EXISTS statement for a single table (SQLite).
fn generate_create_table(table: &TableDef) -> String {
    let mut sql = format!("CREATE TABLE IF NOT EXISTS {} (\n", table.name);

    let col_count = table.columns.len();
    for (i, col) in table.columns.iter().enumerate() {
        sql.push_str("    ");
        sql.push_str(&col.name);
        sql.push(' ');
        sql.push_str(&sqlite_type(&col.col_type));

        if col.primary_key {
            sql.push_str(" PRIMARY KEY");
            if let Some(ref default) = col.default
                && let Some(mapped) = sqlite_default(default)
            {
                sql.push_str(" DEFAULT ");
                sql.push_str(&mapped);
            }
            if let Some(ref fk) = col.foreign_key {
                sql.push_str(&format!(
                    " REFERENCES {}({}) {}",
                    fk.references_table,
                    fk.references_column,
                    sqlite_on_delete(&fk.on_delete)
                ));
            }
        } else if let Some(ref fk) = col.foreign_key {
            if !col.nullable {
                sql.push_str(" NOT NULL");
            }
            sql.push_str(&format!(
                " REFERENCES {}({}) {}",
                fk.references_table,
                fk.references_column,
                sqlite_on_delete(&fk.on_delete)
            ));
            if col.unique {
                sql.push_str(" UNIQUE");
            }
        } else {
            if !col.nullable {
                sql.push_str(" NOT NULL");
            }
            if col.unique {
                sql.push_str(" UNIQUE");
            }
            if let Some(ref default) = col.default
                && let Some(mapped) = sqlite_default(default)
            {
                sql.push_str(" DEFAULT ");
                sql.push_str(&mapped);
            }
        }

        if i < col_count - 1 {
            sql.push(',');
        }
        sql.push('\n');
    }

    sql.push_str(");\n");
    sql
}

/// Generate complete SQLite DDL for the entire schema.
///
/// Returns one string with `PRAGMA foreign_keys = ON` followed by all
/// `CREATE TABLE IF NOT EXISTS` statements in topological order.
pub fn generate_sqlite_ddl(schema: &YAuthSchema) -> String {
    let mut ddl = String::from("PRAGMA foreign_keys = ON;\n\n");
    for (i, table) in schema.tables.iter().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_create_table(table));
    }
    ddl
}

/// Generate DROP TABLE IF EXISTS statement for a single table (SQLite).
pub fn generate_sqlite_drop(table: &TableDef) -> String {
    format!("DROP TABLE IF EXISTS {};\n", table.name)
}

/// Generate DROP TABLE statements for a list of tables in reverse order (SQLite).
pub fn generate_sqlite_drops(tables: &[TableDef]) -> String {
    let mut ddl = String::new();
    for (i, table) in tables.iter().rev().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_sqlite_drop(table));
    }
    ddl
}
