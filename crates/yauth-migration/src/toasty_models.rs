//! Toasty model + scaffolding generator.
//!
//! Emits idiomatic Toasty 0.4 entity structs and the minimum scaffolding
//! a consumer needs to start using the Toasty backend:
//!
//! - `models.rs` — one `#[derive(toasty::Model)]` struct per table with
//!   `jiff::Timestamp` timestamps, `#[serialize(json)]` + natural types
//!   for JSON columns, and `#[belongs_to]` / `#[has_many]` /
//!   `#[has_one]` relationships wired on both sides.
//! - `Toasty.toml` — migration configuration (sequential prefixes,
//!   checksums, statement breakpoints, `yauth_` table prefix).
//! - `bin/toasty-dev.rs` — a thin stub binary the consumer can run to
//!   generate migrations from future model changes.
//!
//! This is **string-based code generation** — `yauth-migration` has zero
//! toasty dependencies and none of the generated code imports types
//! from this crate.

use crate::collector::YAuthSchema;
use crate::types::{ColumnDef, ColumnType, ForeignKey, TableDef};
use std::collections::HashMap;

/// Map an abstract column type to the idiomatic Toasty 0.4 Rust type.
///
/// Timestamps use `jiff::Timestamp` (requires the `jiff` feature on toasty).
/// JSON columns default to `serde_json::Value`; the field is tagged with
/// `#[serialize(json)]` at the call site.
fn rust_type(col: &ColumnDef) -> String {
    let base = match col.col_type {
        ColumnType::Uuid => "uuid::Uuid",
        ColumnType::Varchar | ColumnType::VarcharN(_) | ColumnType::Text => "String",
        ColumnType::Boolean => "bool",
        ColumnType::DateTime => "jiff::Timestamp",
        ColumnType::Json => "serde_json::Value",
        ColumnType::Int => "i64",
        ColumnType::SmallInt => "i64",
    };
    if col.nullable {
        format!("Option<{base}>")
    } else {
        base.to_string()
    }
}

/// Singularize a table name in the simple cases yauth actually uses.
///
/// `audit_log` → `audit_log`, `users` → `user`, `passkeys` → `passkey`,
/// `totp_secrets` → `totp_secret`, `oauth2_clients` → `oauth2_client`.
/// Names that don't end in `s` are left alone.
fn singularize(word: &str) -> String {
    if word.ends_with("ies") && word.len() > 3 {
        // e.g. `entities` → `entity`
        format!("{}y", &word[..word.len() - 3])
    } else if word.ends_with('s') && !word.ends_with("ss") && word.len() > 1 {
        word[..word.len() - 1].to_string()
    } else {
        word.to_string()
    }
}

/// Convert a table name like `yauth_totp_secrets` to a PascalCase singular
/// model name like `YauthTotpSecret`.
fn model_name(table_name: &str) -> String {
    let segments: Vec<&str> = table_name.split('_').collect();
    let mut out = String::new();
    for (i, segment) in segments.iter().enumerate() {
        let word: String = if i == segments.len() - 1 {
            singularize(segment)
        } else {
            (*segment).to_string()
        };
        let mut chars = word.chars();
        if let Some(c) = chars.next() {
            out.extend(c.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    out
}

/// The `#[table = "..."]` attribute value — table name minus the prefix.
fn table_attr(table_name: &str, prefix: &str) -> String {
    table_name
        .strip_prefix(prefix)
        .unwrap_or(table_name)
        .to_string()
}

/// One back-reference from a parent table to a child FK. Stored per
/// parent table in `build_child_map`.
#[derive(Debug, Clone)]
struct ChildRef {
    child_table: String,
    child_column: String,
    _fk: ForeignKey,
}

/// Build a map from parent table name to the list of child references
/// that target it. Used to emit `#[has_many]` / `#[has_one]` on the
/// parent.
fn build_child_map(schema: &YAuthSchema) -> HashMap<String, Vec<ChildRef>> {
    let mut map: HashMap<String, Vec<ChildRef>> = HashMap::new();
    for table in &schema.tables {
        for col in &table.columns {
            if let Some(fk) = &col.foreign_key {
                if fk.references_table == table.name {
                    // Self-referential FK — skip the has_* synthesis.
                    continue;
                }
                map.entry(fk.references_table.clone())
                    .or_default()
                    .push(ChildRef {
                        child_table: table.name.clone(),
                        child_column: col.name.clone(),
                        _fk: fk.clone(),
                    });
            }
        }
    }
    map
}

/// Decide whether a child relationship should be expressed as `has_one`
/// or `has_many`. A child FK column that is `#[unique]` OR that is the
/// table's primary key (implying a 1:1 row-per-parent pattern) produces
/// `has_one`; otherwise `has_many`.
fn is_has_one(schema: &YAuthSchema, child_table: &str, child_column: &str) -> bool {
    let Some(table) = schema.tables.iter().find(|t| t.name == child_table) else {
        return false;
    };
    table
        .columns
        .iter()
        .find(|c| c.name == child_column)
        .map(|c| c.unique || c.primary_key)
        .unwrap_or(false)
}

/// Build a singular field name for the parent side of a relationship.
///
/// For `has_many`: plural singular — e.g. `sessions`, `api_keys`.
/// For `has_one`: singularized child name — e.g. `password`, `totp_secret`.
fn parent_field_name(child_table: &str, prefix: &str, has_one: bool) -> String {
    let base = child_table.strip_prefix(prefix).unwrap_or(child_table);
    if has_one {
        singularize(base)
    } else {
        base.to_string()
    }
}

/// Generate one `#[derive(toasty::Model)]` struct for a table.
fn generate_model(
    table: &TableDef,
    prefix: &str,
    child_map: &HashMap<String, Vec<ChildRef>>,
    schema: &YAuthSchema,
) -> String {
    let name = model_name(&table.name);
    let table_val = table_attr(&table.name, prefix);
    let mut out = String::new();

    out.push_str(&format!("/// Toasty model for `{}`.\n", table.name));
    out.push_str("#[derive(Debug, toasty::Model)]\n");
    out.push_str(&format!("#[table = \"{}\"]\n", table_val));
    out.push_str(&format!("pub struct {} {{\n", name));

    // Concrete columns.
    for col in &table.columns {
        if col.primary_key {
            out.push_str("    #[key]\n");
            if col.col_type == ColumnType::Uuid {
                out.push_str("    #[auto]\n");
            }
        }
        if col.unique && !col.primary_key {
            out.push_str("    #[unique]\n");
        }

        // JSON columns: tag with #[serialize(json)] so Toasty round-trips
        // the field as application/json rather than an opaque blob.
        if col.col_type == ColumnType::Json {
            out.push_str("    #[serialize(json)]\n");
        }

        let rust_ty = rust_type(col);
        out.push_str(&format!("    pub {}: {},\n", col.name, rust_ty));

        // BelongsTo virtual field on the child side.
        if let Some(fk) = col
            .foreign_key
            .as_ref()
            .filter(|fk| fk.references_table != table.name)
        {
            let parent_model = model_name(&fk.references_table);
            let rel_field = col
                .name
                .strip_suffix("_id")
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{}_ref", col.name));
            out.push_str(&format!(
                "    #[belongs_to(key = {}, references = {})]\n",
                col.name, fk.references_column
            ));
            out.push_str(&format!(
                "    pub {}: toasty::BelongsTo<{}>,\n",
                rel_field, parent_model
            ));
        }
    }

    // HasMany / HasOne virtual fields on the parent side.
    if let Some(children) = child_map.get(&table.name) {
        for child in children {
            let child_model = model_name(&child.child_table);
            let has_one = is_has_one(schema, &child.child_table, &child.child_column);
            let field = parent_field_name(&child.child_table, prefix, has_one);
            if has_one {
                out.push_str("    #[has_one]\n");
                out.push_str(&format!(
                    "    pub {}: toasty::HasOne<{}>,\n",
                    field, child_model
                ));
            } else {
                out.push_str("    #[has_many]\n");
                out.push_str(&format!(
                    "    pub {}: toasty::HasMany<{}>,\n",
                    field, child_model
                ));
            }
        }
    }

    out.push_str("}\n");
    out
}

/// Generate the top-level `models.rs` with every entity struct.
fn generate_models_mod(schema: &YAuthSchema, prefix: &str) -> String {
    let child_map = build_child_map(schema);

    let mut out = String::from("// @generated by cargo-yauth -- DO NOT EDIT\n");
    out.push_str("//\n");
    out.push_str("// Toasty 0.4 model definitions for yauth tables.\n");
    out.push_str("//\n");
    out.push_str("// Usage:\n");
    out.push_str(&format!(
        "//     let db = toasty::Db::builder()\n\
         //         .table_name_prefix(\"{}\")\n\
         //         .models(toasty::models!(crate::*))\n\
         //         .connect(\"sqlite://yauth.db\")\n\
         //         .await?;\n\
         //     // Production: apply the tracked migration chain (see Toasty.toml):\n\
         //     // yauth_toasty::apply_migrations(&db).await?;\n\n",
        prefix
    ));

    for (i, table) in schema.tables.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&generate_model(table, prefix, &child_map, schema));
    }

    out
}

/// Generate the `Toasty.toml` configuration file for the migration CLI.
fn generate_toasty_toml(prefix: &str) -> String {
    format!(
        "# Toasty migration configuration — generated by cargo-yauth.\n\
         # Safe to edit by hand once committed.\n\n\
         [migration]\n\
         # Migration artifacts live here relative to the crate root.\n\
         path = \"toasty\"\n\
         # Sequential numeric prefix: 0000_, 0001_, 0002_, ...\n\
         # Chosen over timestamps for deterministic ordering in embedded builds.\n\
         prefix_style = \"Sequential\"\n\
         # Insert `-- #[toasty::breakpoint]` comments between DDL statements so\n\
         # the applier can split multi-statement files per driver (SQLite only\n\
         # accepts one statement per execute()).\n\
         statement_breakpoints = true\n\
         # SHA-256 checksum stored per migration so accidental edits to\n\
         # already-applied files fail fast at apply time.\n\
         checksums = true\n\n\
         [schema]\n\
         # All yauth tables wear the same prefix as other backends.\n\
         table_name_prefix = \"{}\"\n",
        prefix
    )
}

/// Generate a thin dev-CLI binary stub. The consumer runs this to generate
/// new migration files when they change their model definitions.
fn generate_toasty_dev_bin() -> String {
    r#"//! Dev-only CLI for generating Toasty migrations from model changes.
//!
//! Run with:
//!     cargo run --bin toasty-dev --features dev-cli -- migration generate --name add_passkey_fields
//!     cargo run --bin toasty-dev --features dev-cli -- migration status
//!
//! Not shipped to consumers — gate behind `required-features = ["dev-cli"]`
//! in Cargo.toml so it never lands in a published binary.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Build a Db handle with every model registered. No actual database
    // connection is needed for schema inspection or migration generation.
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(toasty::models!(crate::*))
        .connect("sqlite::memory:")
        .await?;

    // Delegate to toasty-cli (or implement your own subcommand dispatch).
    // See the yauth-toasty crate's own `toasty-dev.rs` for a complete
    // example including migration generate / status / apply.
    eprintln!(
        "toasty-dev stub — wire this to toasty-cli or your preferred\n\
         migration flow. The generated models.rs lives next to this file."
    );

    let _ = db;
    Ok(())
}
"#
    .to_string()
}

/// Generate all Toasty scaffolding files for the schema.
///
/// Returns a list of `(relative_path, content)` pairs:
/// - `models.rs` — idiomatic entity structs with relationships and
///   `jiff::Timestamp` columns.
/// - `Toasty.toml` — migration CLI configuration.
/// - `bin/toasty-dev.rs` — dev CLI binary stub.
///
/// Notably: **no SQL files**. Toasty's migration chain is generated by
/// `toasty-cli` at develop time, not by this code generator.
pub fn generate_toasty_models(schema: &YAuthSchema, prefix: &str) -> Vec<(String, String)> {
    vec![
        ("models.rs".to_string(), generate_models_mod(schema, prefix)),
        ("Toasty.toml".to_string(), generate_toasty_toml(prefix)),
        ("bin/toasty-dev.rs".to_string(), generate_toasty_dev_bin()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collect_schema, collect_schema_for_plugins, core_schema, plugin_schemas};

    fn file<'a>(files: &'a [(String, String)], name: &str) -> &'a str {
        files
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.as_str())
            .unwrap_or_else(|| panic!("expected {name} to be emitted"))
    }

    #[test]
    fn generates_core_models_and_scaffolding() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");

        // Three scaffolding files — and not a hand-rolled SQL among them.
        assert_eq!(files.len(), 3);
        for (name, _) in &files {
            assert!(!name.ends_with(".sql"), "no SQL should be emitted: {name}");
        }

        let content = file(&files, "models.rs");
        assert!(content.contains("#[derive(Debug, toasty::Model)]"));
        assert!(content.contains("#[table = \"users\"]"));
        // Singularized model name (was "YauthUsers" before).
        assert!(content.contains("pub struct YauthUser"));
        assert!(content.contains("pub id: uuid::Uuid"));
        assert!(content.contains("pub email: String"));
        assert!(content.contains("pub email_verified: bool"));
        assert!(content.contains("#[key]"));
        assert!(content.contains("#[auto]"));
    }

    #[test]
    fn generates_belongs_to_and_has_many_relationships() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "models.rs");

        // Child side: sessions.user_id → users.id
        assert!(content.contains("#[belongs_to(key = user_id, references = id)]"));
        assert!(content.contains("pub user: toasty::BelongsTo<YauthUser>"));

        // Parent side: users has_many sessions
        assert!(content.contains("#[has_many]"));
        assert!(content.contains("pub sessions: toasty::HasMany<YauthSession>"));
    }

    #[test]
    fn datetime_columns_use_jiff_timestamp() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "models.rs");
        assert!(content.contains("pub created_at: jiff::Timestamp"));
        assert!(!content.contains("pub created_at: String"));
    }

    #[test]
    fn json_columns_use_serialize_json_with_natural_type() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "models.rs");
        assert!(content.contains("#[serialize(json)]"));
        assert!(content.contains("pub metadata: Option<serde_json::Value>"));
    }

    #[test]
    fn plugin_schema_emits_has_one_on_user_password() {
        let schema =
            collect_schema(vec![core_schema(), plugin_schemas::email_password_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "models.rs");

        // passwords.user_id is #[unique] → one-to-one.
        assert!(content.contains("#[has_one]"));
        assert!(content.contains("pub password: toasty::HasOne<YauthPassword>"));
    }

    #[test]
    fn custom_prefix_strips_from_table_attr_only() {
        let schema = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
        let files = generate_toasty_models(&schema, "auth_");
        let content = file(&files, "models.rs");
        // The `#[table = "..."]` attr always has the prefix stripped.
        assert!(content.contains("#[table = \"users\"]"));
        // Model name is singularized + PascalCased; prefix segment kept.
        assert!(content.contains("pub struct AuthUser"));
        // The rendered `#[table = "..."]` attr should never include the
        // full prefixed form.
        assert!(!content.contains("#[table = \"auth_users\"]"));
    }

    #[test]
    fn toasty_toml_has_sequential_prefix_and_checksums() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "Toasty.toml");
        assert!(content.contains("[migration]"));
        assert!(content.contains("prefix_style = \"Sequential\""));
        assert!(content.contains("statement_breakpoints = true"));
        assert!(content.contains("checksums = true"));
        assert!(content.contains("table_name_prefix = \"yauth_\""));
    }

    #[test]
    fn toasty_dev_stub_has_models_registration() {
        let schema = collect_schema(vec![core_schema()]).unwrap();
        let files = generate_toasty_models(&schema, "yauth_");
        let content = file(&files, "bin/toasty-dev.rs");
        assert!(content.contains("toasty::Db::builder()"));
        assert!(content.contains("toasty::models!(crate::*)"));
        assert!(content.contains("async fn main"));
    }
}
