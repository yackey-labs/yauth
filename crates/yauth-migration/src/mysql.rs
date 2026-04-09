//! MySQL DDL generation.
//!
//! Maps abstract column types to MySQL-compatible types:
//! - UUID -> CHAR(36)
//! - VARCHAR -> VARCHAR(255)
//! - VarcharN(n) -> VARCHAR(n)
//! - BOOLEAN -> TINYINT(1)
//! - DateTime -> DATETIME
//! - Json -> JSON
//! - INT -> INT
//! - SMALLINT -> SMALLINT
//! - TEXT -> TEXT

use std::borrow::Cow;

use super::collector::YAuthSchema;
use super::types::*;

/// Map abstract column type to MySQL type string.
pub(crate) fn mysql_type(col_type: &ColumnType) -> Cow<'static, str> {
    match col_type {
        ColumnType::Uuid => Cow::Borrowed("CHAR(36)"),
        ColumnType::Varchar => Cow::Borrowed("VARCHAR(255)"),
        ColumnType::VarcharN(n) => Cow::Owned(format!("VARCHAR({n})")),
        ColumnType::Boolean => Cow::Borrowed("TINYINT(1)"),
        ColumnType::DateTime => Cow::Borrowed("DATETIME"),
        ColumnType::Json => Cow::Borrowed("JSON"),
        ColumnType::Int => Cow::Borrowed("INT"),
        ColumnType::SmallInt => Cow::Borrowed("SMALLINT"),
        ColumnType::Text => Cow::Borrowed("TEXT"),
    }
}

/// Map OnDelete action to MySQL clause.
fn mysql_on_delete(action: &OnDelete) -> &'static str {
    match action {
        OnDelete::Cascade => "ON DELETE CASCADE",
        OnDelete::SetNull => "ON DELETE SET NULL",
        OnDelete::Restrict => "ON DELETE RESTRICT",
        OnDelete::NoAction => "ON DELETE NO ACTION",
    }
}

/// Map a Postgres default expression to its MySQL equivalent.
pub(crate) fn mysql_default(pg_default: &str) -> Option<Cow<'static, str>> {
    match pg_default {
        "gen_random_uuid()" => None,
        "now()" => Some(Cow::Borrowed("CURRENT_TIMESTAMP")),
        other => Some(Cow::Owned(other.to_string())),
    }
}

/// Generate a CREATE TABLE IF NOT EXISTS statement for a single table (MySQL).
///
/// MySQL silently ignores inline `REFERENCES` on columns; foreign key constraints
/// must be declared as separate `FOREIGN KEY (col) REFERENCES table(col)` lines
/// after all column definitions.
fn generate_create_table(table: &TableDef) -> String {
    let mut sql = String::new();
    if let Some(ref desc) = table.description {
        sql.push_str(&format!("-- {desc}\n"));
    }
    sql.push_str(&format!("CREATE TABLE IF NOT EXISTS `{}` (\n", table.name));

    // Collect FK constraints to emit after all columns.
    let mut fk_constraints: Vec<String> = Vec::new();

    let col_count = table.columns.len();
    for (i, col) in table.columns.iter().enumerate() {
        sql.push_str("    `");
        sql.push_str(&col.name);
        sql.push_str("` ");
        sql.push_str(&mysql_type(&col.col_type));

        if col.primary_key {
            sql.push_str(" PRIMARY KEY");
            if let Some(ref default) = col.default
                && let Some(mapped) = mysql_default(default)
            {
                sql.push_str(" DEFAULT ");
                sql.push_str(&mapped);
            }
        } else {
            if !col.nullable {
                sql.push_str(" NOT NULL");
            }
            if col.unique {
                sql.push_str(" UNIQUE");
            }
            if let Some(ref default) = col.default
                && let Some(mapped) = mysql_default(default)
            {
                sql.push_str(" DEFAULT ");
                sql.push_str(&mapped);
            }
        }

        // Collect FK as a table-level constraint (never inline).
        if let Some(ref fk) = col.foreign_key {
            fk_constraints.push(format!(
                "    FOREIGN KEY (`{}`) REFERENCES `{}`(`{}`) {}",
                col.name,
                fk.references_table,
                fk.references_column,
                mysql_on_delete(&fk.on_delete)
            ));
        }

        // Always add comma after columns -- FK constraints or closing paren follow.
        if i < col_count - 1 || !fk_constraints.is_empty() {
            sql.push(',');
        }
        sql.push('\n');
    }

    // Emit collected FK constraints as table-level constraints.
    for (i, fk) in fk_constraints.iter().enumerate() {
        sql.push_str(fk);
        if i < fk_constraints.len() - 1 {
            sql.push(',');
        }
        sql.push('\n');
    }

    sql.push_str(") ENGINE=InnoDB;\n");
    sql
}

/// Generate complete MySQL DDL for the entire schema.
pub fn generate_mysql_ddl(schema: &YAuthSchema) -> String {
    let mut ddl = String::new();
    for (i, table) in schema.tables.iter().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_create_table(table));
    }
    ddl
}

/// Generate DROP TABLE IF EXISTS statement for a single table (MySQL).
pub fn generate_mysql_drop(table: &TableDef) -> String {
    format!("DROP TABLE IF EXISTS `{}`;\n", table.name)
}

/// Generate DROP TABLE statements for a list of tables in reverse order (MySQL).
pub fn generate_mysql_drops(tables: &[TableDef]) -> String {
    let mut ddl = String::new();
    for (i, table) in tables.iter().rev().enumerate() {
        if i > 0 {
            ddl.push('\n');
        }
        ddl.push_str(&generate_mysql_drop(table));
    }
    ddl
}
