//! SeaORM entity code generator.
//!
//! Generates valid Rust source text (as a `String`) containing SeaORM
//! `DeriveEntityModel` entity definitions for each table in the schema.
//! This is **string-based code generation** -- the crate has zero sea-orm dependencies.

use crate::collector::YAuthSchema;
use crate::types::{ColumnDef, ColumnType, OnDelete, TableDef};

/// Map abstract column type to a SeaORM Rust type for the `Model` struct field.
fn rust_type(col: &ColumnDef) -> String {
    let base = match col.col_type {
        ColumnType::Uuid => "Uuid",
        ColumnType::Varchar | ColumnType::VarcharN(_) | ColumnType::Text => "String",
        ColumnType::Boolean => "bool",
        ColumnType::DateTime => "DateTimeWithTimeZone",
        ColumnType::Json => "serde_json::Value",
        ColumnType::Int => "i32",
        ColumnType::SmallInt => "i16",
    };
    if col.nullable {
        format!("Option<{base}>")
    } else {
        base.to_string()
    }
}

/// Map abstract column type to a SeaORM `column_type` attribute string.
fn sea_orm_column_type(col: &ColumnDef) -> Option<String> {
    let attr = match col.col_type {
        ColumnType::Uuid => "Uuid",
        ColumnType::Text => "Text",
        ColumnType::Json => "JsonBinary",
        // Varchar, VarcharN, Boolean, DateTime, Int, SmallInt use SeaORM defaults
        _ => return None,
    };
    Some(attr.to_string())
}

/// Convert a table name like `yauth_users` to a module name like `users`.
/// Strips the prefix if present.
fn module_name(table_name: &str, prefix: &str) -> String {
    table_name
        .strip_prefix(prefix)
        .unwrap_or(table_name)
        .to_string()
}

/// Generate a single SeaORM entity module for one table.
fn generate_entity_module(table: &TableDef, prefix: &str) -> String {
    let mut out = String::new();

    out.push_str(&format!("//! SeaORM entity for `{}`.\n\n", table.name));
    out.push_str("use sea_orm::entity::prelude::*;\n");

    // Check if we need DateTimeWithTimeZone
    let needs_dtwtz = table
        .columns
        .iter()
        .any(|c| c.col_type == ColumnType::DateTime);
    if needs_dtwtz {
        out.push_str("use sea_orm::prelude::DateTimeWithTimeZone;\n");
    }

    // Check if we need uuid
    let needs_uuid = table.columns.iter().any(|c| c.col_type == ColumnType::Uuid);
    if needs_uuid {
        out.push_str("use uuid::Uuid;\n");
    }

    out.push('\n');

    // Model struct
    out.push_str("#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]\n");
    out.push_str(&format!("#[sea_orm(table_name = \"{}\")]\n", table.name));
    out.push_str("pub struct Model {\n");

    for col in &table.columns {
        let mut attrs = Vec::new();

        if col.primary_key {
            attrs.push("primary_key".to_string());
            attrs.push("auto_increment = false".to_string());
        }

        if let Some(ct) = sea_orm_column_type(col) {
            attrs.push(format!("column_type = \"{}\"", ct));
        }

        if col.nullable && !col.primary_key {
            attrs.push("nullable".to_string());
        }

        if !attrs.is_empty() {
            out.push_str(&format!("    #[sea_orm({})]\n", attrs.join(", ")));
        }

        let rust_ty = rust_type(col);
        out.push_str(&format!("    pub {}: {},\n", col.name, rust_ty));
    }

    out.push_str("}\n\n");

    // Relation enum
    let fk_cols: Vec<&ColumnDef> = table
        .columns
        .iter()
        .filter(|c| {
            c.foreign_key.is_some()
                && c.foreign_key.as_ref().unwrap().references_table != table.name
        })
        .collect();

    out.push_str("#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]\n");
    out.push_str("pub enum Relation {\n");

    for col in &fk_cols {
        let fk = col.foreign_key.as_ref().unwrap();
        let ref_mod = module_name(&fk.references_table, prefix);
        let on_delete = match fk.on_delete {
            OnDelete::Cascade => "Cascade",
            OnDelete::SetNull => "SetNull",
            OnDelete::Restrict => "Restrict",
            OnDelete::NoAction => "NoAction",
        };

        // Derive a variant name from the referenced table module
        let variant_name = to_pascal_case(&ref_mod);

        out.push_str(&format!(
            "    #[sea_orm(\n        belongs_to = \"super::{}::Entity\",\n        from = \"Column::{}\",\n        to = \"super::{}::Column::{}\",\n        on_delete = \"{}\"\n    )]\n    {},\n",
            ref_mod,
            to_pascal_case(&col.name),
            ref_mod,
            to_pascal_case(&fk.references_column),
            on_delete,
            variant_name,
        ));
    }

    out.push_str("}\n\n");

    // Related impls for each FK
    for col in &fk_cols {
        let fk = col.foreign_key.as_ref().unwrap();
        let ref_mod = module_name(&fk.references_table, prefix);
        let variant_name = to_pascal_case(&ref_mod);

        out.push_str(&format!(
            "impl Related<super::{}::Entity> for Entity {{\n    fn to() -> RelationDef {{\n        Relation::{}.def()\n    }}\n}}\n\n",
            ref_mod, variant_name,
        ));
    }

    // ActiveModelBehavior
    out.push_str("impl ActiveModelBehavior for ActiveModel {}\n");

    out
}

/// Convert snake_case to PascalCase.
fn to_pascal_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Generate the `mod.rs` for the entities module.
fn generate_entities_mod(tables: &[TableDef], prefix: &str) -> String {
    let mut out = String::from("// @generated by cargo-yauth -- DO NOT EDIT\n\n");

    for table in tables {
        let mod_name = module_name(&table.name, prefix);
        out.push_str(&format!("pub mod {};\n", mod_name));
    }

    out.push_str("\npub mod prelude {\n");
    for table in tables {
        let mod_name = module_name(&table.name, prefix);
        out.push_str(&format!(
            "    pub use super::{}::Entity as {};\n",
            mod_name,
            to_pascal_case(&mod_name)
        ));
    }
    out.push_str("}\n");

    out
}

/// Generate SeaORM entity files for all tables in the schema.
///
/// Returns a list of `(relative_path, content)` pairs where each path is
/// relative to the entities output directory.
pub fn generate_seaorm_entities(schema: &YAuthSchema, prefix: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();

    // mod.rs
    files.push((
        "mod.rs".to_string(),
        generate_entities_mod(&schema.tables, prefix),
    ));

    // One file per entity
    for table in &schema.tables {
        let mod_name = module_name(&table.name, prefix);
        let content = generate_entity_module(table, prefix);
        files.push((format!("{}.rs", mod_name), content));
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collect_schema, collect_schema_for_plugins, core_schema, plugin_schemas};

    #[test]
    fn generates_core_entities() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        // Should have mod.rs + one file per table
        assert!(files.len() >= 4); // mod.rs + users + sessions + audit_log

        // Check mod.rs
        let (name, content) = &files[0];
        assert_eq!(name, "mod.rs");
        assert!(content.contains("pub mod users;"));
        assert!(content.contains("pub mod sessions;"));
        assert!(content.contains("pub mod audit_log;"));
        assert!(content.contains("pub use super::users::Entity as Users;"));

        // Check users entity
        let users_file = files.iter().find(|(n, _)| n == "users.rs").unwrap();
        assert!(users_file.1.contains("DeriveEntityModel"));
        assert!(users_file.1.contains("table_name = \"yauth_users\""));
        assert!(users_file.1.contains("pub id: Uuid"));
        assert!(users_file.1.contains("pub email: String"));
        assert!(users_file.1.contains("pub email_verified: bool"));
        assert!(
            users_file
                .1
                .contains("pub created_at: DateTimeWithTimeZone")
        );
        assert!(users_file.1.contains("pub display_name: Option<String>"));
        assert!(users_file.1.contains("primary_key"));
        assert!(users_file.1.contains("ActiveModelBehavior"));
    }

    #[test]
    fn generates_foreign_key_relations() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        // Sessions should have a FK relation to users
        let sessions_file = files.iter().find(|(n, _)| n == "sessions.rs").unwrap();
        assert!(
            sessions_file
                .1
                .contains("belongs_to = \"super::users::Entity\"")
        );
        assert!(sessions_file.1.contains("from = \"Column::UserId\""));
        assert!(
            sessions_file
                .1
                .contains("to = \"super::users::Column::Id\"")
        );
        assert!(sessions_file.1.contains("on_delete = \"Cascade\""));
        assert!(
            sessions_file
                .1
                .contains("impl Related<super::users::Entity>")
        );
    }

    #[test]
    fn generates_plugin_entities() {
        let schema = collect_schema(vec![
            core_schema(),
            plugin_schemas::email_password_schema(),
            plugin_schemas::passkey_schema(),
        ])
        .unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        // Should include password and passkey tables
        let mod_file = files.iter().find(|(n, _)| n == "mod.rs").unwrap();
        assert!(mod_file.1.contains("pub mod passwords;"));
        assert!(mod_file.1.contains("pub mod webauthn_credentials;"));

        // Password entity should have user_id as PK
        let pw_file = files.iter().find(|(n, _)| n == "passwords.rs").unwrap();
        assert!(pw_file.1.contains("table_name = \"yauth_passwords\""));
        assert!(pw_file.1.contains("primary_key"));
    }

    #[test]
    fn nullable_columns_use_option() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        let users_file = files.iter().find(|(n, _)| n == "users.rs").unwrap();
        // display_name is nullable
        assert!(users_file.1.contains("pub display_name: Option<String>"));
        // email is not nullable
        assert!(users_file.1.contains("pub email: String,"));
    }

    #[test]
    fn json_columns_use_jsonb() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        let audit_file = files.iter().find(|(n, _)| n == "audit_log.rs").unwrap();
        assert!(audit_file.1.contains("column_type = \"JsonBinary\""));
        assert!(audit_file.1.contains("serde_json::Value"));
    }

    #[test]
    fn custom_prefix() {
        let schema = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
        let files = generate_seaorm_entities(&schema, "auth_");

        let mod_file = files.iter().find(|(n, _)| n == "mod.rs").unwrap();
        assert!(mod_file.1.contains("pub mod users;"));
        assert!(!mod_file.1.contains("yauth_"));

        let users_file = files.iter().find(|(n, _)| n == "users.rs").unwrap();
        assert!(users_file.1.contains("table_name = \"auth_users\""));
    }

    #[test]
    fn on_delete_set_null() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_seaorm_entities(&schema, "yauth_");

        // audit_log has user_id with ON DELETE SET NULL
        let audit_file = files.iter().find(|(n, _)| n == "audit_log.rs").unwrap();
        assert!(audit_file.1.contains("on_delete = \"SetNull\""));
    }
}
