//! Schema diff engine.
//!
//! Compares two `YAuthSchema` snapshots (previous plugins vs current)
//! and produces incremental SQL operations.

use crate::collector::YAuthSchema;
use crate::mysql::{mysql_default, mysql_type};
use crate::postgres::pg_type;
use crate::sqlite::{sqlite_default, sqlite_type};
use crate::types::TableDef;

/// A single schema change operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaChange {
    /// A new table needs to be created (includes all columns).
    CreateTable(TableDef),
    /// An existing table needs to be dropped.
    DropTable(TableDef),
    /// A new column needs to be added to an existing table.
    AddColumn {
        table_name: String,
        column: crate::types::ColumnDef,
    },
    /// A column needs to be removed from an existing table.
    DropColumn {
        table_name: String,
        column_name: String,
    },
}

/// Compute the diff between two schemas.
///
/// `from` is the previous schema state, `to` is the desired state.
/// Returns a list of changes needed to go from `from` to `to`.
pub fn schema_diff(from: &YAuthSchema, to: &YAuthSchema) -> Vec<SchemaChange> {
    let mut changes = Vec::new();

    let from_tables: std::collections::HashMap<&str, &TableDef> =
        from.tables.iter().map(|t| (t.name.as_str(), t)).collect();
    let to_tables: std::collections::HashMap<&str, &TableDef> =
        to.tables.iter().map(|t| (t.name.as_str(), t)).collect();

    // Tables to create (in `to` but not in `from`) -- preserve topological order
    for table in &to.tables {
        if !from_tables.contains_key(table.name.as_str()) {
            changes.push(SchemaChange::CreateTable(table.clone()));
        }
    }

    // Tables to drop (in `from` but not in `to`) -- reverse topological order
    for table in from.tables.iter().rev() {
        if !to_tables.contains_key(table.name.as_str()) {
            changes.push(SchemaChange::DropTable(table.clone()));
        }
    }

    // Column-level changes for tables that exist in both
    for table in &to.tables {
        if let Some(from_table) = from_tables.get(table.name.as_str()) {
            let from_cols: std::collections::HashSet<&str> =
                from_table.columns.iter().map(|c| c.name.as_str()).collect();
            let to_cols: std::collections::HashSet<&str> =
                table.columns.iter().map(|c| c.name.as_str()).collect();

            // New columns
            for col in &table.columns {
                if !from_cols.contains(col.name.as_str()) {
                    changes.push(SchemaChange::AddColumn {
                        table_name: table.name.clone(),
                        column: col.clone(),
                    });
                }
            }

            // Dropped columns
            for col in &from_table.columns {
                if !to_cols.contains(col.name.as_str()) {
                    changes.push(SchemaChange::DropColumn {
                        table_name: table.name.clone(),
                        column_name: col.name.clone(),
                    });
                }
            }
        }
    }

    changes
}

/// Render schema changes as SQL for the given dialect.
pub fn render_changes_sql(changes: &[SchemaChange], dialect: crate::Dialect) -> (String, String) {
    let mut up_sql = String::new();
    let mut down_sql = String::new();

    for change in changes {
        match change {
            SchemaChange::CreateTable(table) => {
                let schema = YAuthSchema {
                    tables: vec![table.clone()],
                };
                let create = match dialect {
                    crate::Dialect::Postgres => crate::generate_postgres_ddl(&schema),
                    crate::Dialect::Sqlite => {
                        // Don't include PRAGMA for individual table creates
                        generate_single_table_sqlite(table)
                    }
                    crate::Dialect::Mysql => crate::generate_mysql_ddl(&schema),
                };
                up_sql.push_str(&create);
                up_sql.push('\n');

                // Down: drop
                let drop = match dialect {
                    crate::Dialect::Postgres => crate::generate_postgres_drop(table),
                    crate::Dialect::Sqlite => crate::generate_sqlite_drop(table),
                    crate::Dialect::Mysql => crate::generate_mysql_drop(table),
                };
                down_sql.push_str(&drop);
                down_sql.push('\n');
            }
            SchemaChange::DropTable(table) => {
                let drop = match dialect {
                    crate::Dialect::Postgres => crate::generate_postgres_drop(table),
                    crate::Dialect::Sqlite => crate::generate_sqlite_drop(table),
                    crate::Dialect::Mysql => crate::generate_mysql_drop(table),
                };
                up_sql.push_str(&drop);
                up_sql.push('\n');

                // Down: recreate
                let schema = YAuthSchema {
                    tables: vec![table.clone()],
                };
                let create = match dialect {
                    crate::Dialect::Postgres => crate::generate_postgres_ddl(&schema),
                    crate::Dialect::Sqlite => generate_single_table_sqlite(table),
                    crate::Dialect::Mysql => crate::generate_mysql_ddl(&schema),
                };
                down_sql.push_str(&create);
                down_sql.push('\n');
            }
            SchemaChange::AddColumn { table_name, column } => {
                let stmt = render_add_column(table_name, column, dialect);
                up_sql.push_str(&stmt);
                up_sql.push('\n');

                let drop_stmt = render_drop_column(table_name, &column.name, dialect);
                down_sql.push_str(&drop_stmt);
                down_sql.push('\n');
            }
            SchemaChange::DropColumn {
                table_name,
                column_name,
            } => {
                let stmt = render_drop_column(table_name, column_name, dialect);
                up_sql.push_str(&stmt);
                up_sql.push('\n');
                // Down for drop column is hard without the original column def,
                // so we add a comment.
                down_sql.push_str(&format!(
                    "-- TODO: Re-add column {column_name} to {table_name}\n\n"
                ));
            }
        }
    }

    (up_sql, down_sql)
}

fn render_add_column(
    table_name: &str,
    column: &crate::types::ColumnDef,
    dialect: crate::Dialect,
) -> String {
    match dialect {
        crate::Dialect::Postgres => {
            let col_type = pg_type(&column.col_type);
            let mut stmt = format!(
                "ALTER TABLE {} ADD COLUMN {} {}",
                table_name, column.name, col_type
            );
            if !column.nullable && column.default.is_none() {
                // Can't add NOT NULL without a default to a table with existing rows
                stmt.push_str(" NULL");
            } else {
                if !column.nullable {
                    stmt.push_str(" NOT NULL");
                }
                if let Some(ref default) = column.default {
                    stmt.push_str(&format!(" DEFAULT {}", default));
                }
            }
            stmt.push_str(";\n");
            stmt
        }
        crate::Dialect::Sqlite => {
            let col_type = sqlite_type(&column.col_type);
            let mut stmt = format!(
                "ALTER TABLE {} ADD COLUMN {} {}",
                table_name, column.name, col_type
            );
            if !column.nullable && column.default.is_none() {
                stmt.push_str(" NULL");
            } else {
                if !column.nullable {
                    stmt.push_str(" NOT NULL");
                }
                if let Some(ref default) = column.default
                    && let Some(d) = sqlite_default(default)
                {
                    stmt.push_str(&format!(" DEFAULT {}", d));
                }
            }
            stmt.push_str(";\n");
            stmt
        }
        crate::Dialect::Mysql => {
            let col_type = mysql_type(&column.col_type);
            let mut stmt = format!(
                "ALTER TABLE `{}` ADD COLUMN `{}` {}",
                table_name, column.name, col_type
            );
            if !column.nullable && column.default.is_none() {
                stmt.push_str(" NULL");
            } else {
                if !column.nullable {
                    stmt.push_str(" NOT NULL");
                }
                if let Some(ref default) = column.default
                    && let Some(d) = mysql_default(default)
                {
                    stmt.push_str(&format!(" DEFAULT {}", d));
                }
            }
            stmt.push_str(";\n");
            stmt
        }
    }
}

fn render_drop_column(table_name: &str, column_name: &str, dialect: crate::Dialect) -> String {
    match dialect {
        crate::Dialect::Postgres => {
            format!(
                "ALTER TABLE {} DROP COLUMN IF EXISTS {};\n",
                table_name, column_name
            )
        }
        crate::Dialect::Sqlite => {
            format!("ALTER TABLE {} DROP COLUMN {};\n", table_name, column_name)
        }
        crate::Dialect::Mysql => {
            format!(
                "ALTER TABLE `{}` DROP COLUMN `{}`;\n",
                table_name, column_name
            )
        }
    }
}

fn generate_single_table_sqlite(table: &TableDef) -> String {
    // Reuse the full generator but strip the PRAGMA
    let schema = YAuthSchema {
        tables: vec![table.clone()],
    };
    let full = crate::generate_sqlite_ddl(&schema);
    // Strip PRAGMA line
    full.lines()
        .filter(|l| !l.starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim_start_matches('\n')
        .to_string()
        + "\n"
}

/// Format a text diff of two SQL strings for display.
pub fn format_sql_diff(old: &str, new: &str) -> String {
    use similar::{ChangeTag, TextDiff};

    let diff = TextDiff::from_lines(old, new);
    let mut output = String::new();

    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        output.push_str(sign);
        output.push_str(change.as_str().unwrap_or(""));
        if !change.as_str().unwrap_or("").ends_with('\n') {
            output.push('\n');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collect_schema, core_schema, plugin_schemas};

    #[test]
    fn diff_empty_to_core_creates_tables() {
        let from = YAuthSchema { tables: vec![] };
        let to = collect_schema(vec![core_schema()]).unwrap();
        let changes = schema_diff(&from, &to);

        assert_eq!(changes.len(), 6);
        let table_names: Vec<&str> = changes
            .iter()
            .filter_map(|c| match c {
                SchemaChange::CreateTable(t) => Some(t.name.as_str()),
                _ => None,
            })
            .collect();
        for expected in &[
            "yauth_users",
            "yauth_sessions",
            "yauth_audit_log",
            "yauth_challenges",
            "yauth_rate_limits",
            "yauth_revocations",
        ] {
            assert!(table_names.contains(expected), "Missing table: {expected}");
        }
    }

    #[test]
    fn diff_add_plugin_creates_plugin_tables() {
        let from = collect_schema(vec![core_schema()]).unwrap();
        let to = collect_schema(vec![core_schema(), plugin_schemas::mfa_schema()]).unwrap();

        let changes = schema_diff(&from, &to);
        assert_eq!(changes.len(), 2);
        assert!(
            matches!(&changes[0], SchemaChange::CreateTable(t) if t.name == "yauth_totp_secrets")
        );
        assert!(
            matches!(&changes[1], SchemaChange::CreateTable(t) if t.name == "yauth_backup_codes")
        );
    }

    #[test]
    fn diff_remove_plugin_drops_plugin_tables() {
        let from = collect_schema(vec![core_schema(), plugin_schemas::passkey_schema()]).unwrap();
        let to = collect_schema(vec![core_schema()]).unwrap();

        let changes = schema_diff(&from, &to);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], SchemaChange::DropTable(t) if t.name == "yauth_webauthn_credentials")
        );
    }

    #[test]
    fn diff_no_changes() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let changes = schema_diff(&schema, &schema);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_add_mfa_produces_valid_postgres_sql() {
        let from = collect_schema(vec![core_schema()]).unwrap();
        let to = collect_schema(vec![core_schema(), plugin_schemas::mfa_schema()]).unwrap();

        let changes = schema_diff(&from, &to);
        let (up, down) = render_changes_sql(&changes, crate::Dialect::Postgres);

        assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_totp_secrets"));
        assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_backup_codes"));
        assert!(down.contains("DROP TABLE IF EXISTS yauth_totp_secrets CASCADE"));
        assert!(down.contains("DROP TABLE IF EXISTS yauth_backup_codes CASCADE"));
    }

    #[test]
    fn diff_add_mfa_produces_valid_sqlite_sql() {
        let from = collect_schema(vec![core_schema()]).unwrap();
        let to = collect_schema(vec![core_schema(), plugin_schemas::mfa_schema()]).unwrap();

        let changes = schema_diff(&from, &to);
        let (up, _down) = render_changes_sql(&changes, crate::Dialect::Sqlite);

        assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_totp_secrets"));
        assert!(!up.contains("PRAGMA")); // Individual table creates shouldn't have PRAGMA
    }

    #[test]
    fn diff_add_mfa_produces_valid_mysql_sql() {
        let from = collect_schema(vec![core_schema()]).unwrap();
        let to = collect_schema(vec![core_schema(), plugin_schemas::mfa_schema()]).unwrap();

        let changes = schema_diff(&from, &to);
        let (up, _down) = render_changes_sql(&changes, crate::Dialect::Mysql);

        assert!(up.contains("CREATE TABLE IF NOT EXISTS `yauth_totp_secrets`"));
        assert!(up.contains("ENGINE=InnoDB"));
    }

    #[test]
    fn diff_complex_add_and_remove() {
        // Start with email-password + passkey, end with email-password + mfa
        let from = collect_schema(vec![
            core_schema(),
            plugin_schemas::email_password_schema(),
            plugin_schemas::passkey_schema(),
        ])
        .unwrap();
        let to = collect_schema(vec![
            core_schema(),
            plugin_schemas::email_password_schema(),
            plugin_schemas::mfa_schema(),
        ])
        .unwrap();

        let changes = schema_diff(&from, &to);

        // Should create mfa tables and drop passkey table
        let creates: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, SchemaChange::CreateTable(_)))
            .collect();
        let drops: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, SchemaChange::DropTable(_)))
            .collect();

        assert_eq!(creates.len(), 2); // totp_secrets + backup_codes
        assert_eq!(drops.len(), 1); // webauthn_credentials
    }

    #[test]
    fn format_diff_shows_additions() {
        let old = "line1\nline2\n";
        let new = "line1\nline2\nline3\n";
        let diff = format_sql_diff(old, new);
        assert!(diff.contains("+line3"));
    }
}
