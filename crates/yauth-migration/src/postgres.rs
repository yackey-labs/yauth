//! Postgres DDL generation.

use super::collector::YAuthSchema;
use super::types::*;

use std::borrow::Cow;

/// Map abstract column type to Postgres type string.
pub(crate) fn pg_type(col_type: &ColumnType) -> Cow<'static, str> {
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

/// Map OnDelete action to Postgres clause.
fn pg_on_delete(action: &OnDelete) -> &'static str {
    match action {
        OnDelete::Cascade => "ON DELETE CASCADE",
        OnDelete::SetNull => "ON DELETE SET NULL",
        OnDelete::Restrict => "ON DELETE RESTRICT",
        OnDelete::NoAction => "ON DELETE NO ACTION",
    }
}

/// Generate a CREATE TABLE IF NOT EXISTS statement for a single table.
fn generate_create_table(table: &TableDef) -> String {
    let mut sql = String::new();
    if let Some(ref desc) = table.description {
        sql.push_str(&format!("-- {desc}\n"));
    }
    sql.push_str(&format!("CREATE TABLE IF NOT EXISTS {} (\n", table.name));

    let col_count = table.columns.len();
    for (i, col) in table.columns.iter().enumerate() {
        sql.push_str("    ");
        sql.push_str(&col.name);
        sql.push(' ');
        sql.push_str(&pg_type(&col.col_type));

        if col.primary_key {
            sql.push_str(" PRIMARY KEY");
            if let Some(ref default) = col.default {
                sql.push_str(" DEFAULT ");
                sql.push_str(default);
            }
            // PK can also have a FK reference (e.g., yauth_passwords.user_id)
            if let Some(ref fk) = col.foreign_key {
                sql.push_str(&format!(
                    " REFERENCES {}({}) {}",
                    fk.references_table,
                    fk.references_column,
                    pg_on_delete(&fk.on_delete)
                ));
            }
        } else if let Some(ref fk) = col.foreign_key {
            // FK columns: [NOT NULL] REFERENCES ... [UNIQUE]
            if !col.nullable {
                sql.push_str(" NOT NULL");
            }
            sql.push_str(&format!(
                " REFERENCES {}({}) {}",
                fk.references_table,
                fk.references_column,
                pg_on_delete(&fk.on_delete)
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
            if let Some(ref default) = col.default {
                sql.push_str(" DEFAULT ");
                sql.push_str(default);
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

/// Generate complete Postgres DDL for the entire schema.
///
/// Returns one string with all CREATE TABLE IF NOT EXISTS statements,
/// in topological order (dependencies first).
pub fn generate_postgres_ddl(schema: &YAuthSchema) -> String {
    let mut ddl = String::new();
    for (i, table) in schema.tables.iter().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_create_table(table));
    }
    ddl
}

/// Generate a DROP TABLE IF EXISTS statement for a single table.
pub fn generate_postgres_drop(table: &TableDef) -> String {
    format!("DROP TABLE IF EXISTS {} CASCADE;\n", table.name)
}

/// Generate DROP TABLE statements for a list of tables in reverse order.
pub fn generate_postgres_drops(tables: &[TableDef]) -> String {
    let mut ddl = String::new();
    for (i, table) in tables.iter().rev().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_postgres_drop(table));
    }
    ddl
}
