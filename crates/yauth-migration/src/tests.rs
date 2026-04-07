//! Unit tests for the declarative schema system.

use super::*;

// -- Basic structure tests --

#[test]
fn core_schema_has_six_tables() {
    let tables = core_schema();
    assert_eq!(tables.len(), 6);
    assert_eq!(tables[0].name, "yauth_users");
    assert_eq!(tables[1].name, "yauth_sessions");
    assert_eq!(tables[2].name, "yauth_audit_log");
    assert_eq!(tables[3].name, "yauth_challenges");
    assert_eq!(tables[4].name, "yauth_rate_limits");
    assert_eq!(tables[5].name, "yauth_revocations");
}

#[test]
fn users_table_columns_match() {
    let tables = core_schema();
    let users = &tables[0];
    assert_eq!(users.columns.len(), 10);
    assert_eq!(users.columns[0].name, "id");
    assert!(users.columns[0].primary_key);
    assert_eq!(users.columns[1].name, "email");
    assert!(users.columns[1].unique);
}

#[test]
fn topological_sort_puts_users_first() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    assert_eq!(schema.tables[0].name, "yauth_users");
    let session_idx = schema
        .tables
        .iter()
        .position(|t| t.name == "yauth_sessions")
        .unwrap();
    let users_idx = schema
        .tables
        .iter()
        .position(|t| t.name == "yauth_users")
        .unwrap();
    assert!(users_idx < session_idx);
}

#[test]
fn topological_sort_preserves_input_order() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let session_idx = schema
        .tables
        .iter()
        .position(|t| t.name == "yauth_sessions")
        .unwrap();
    let audit_idx = schema
        .tables
        .iter()
        .position(|t| t.name == "yauth_audit_log")
        .unwrap();
    assert!(
        session_idx < audit_idx,
        "sessions (pos {}) should come before audit_log (pos {})",
        session_idx,
        audit_idx,
    );
}

#[test]
fn duplicate_table_returns_error() {
    let result = collect_schema(vec![core_schema(), core_schema()]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("duplicate table"),
        "expected duplicate error, got: {err}"
    );
}

#[test]
fn schema_hash_is_deterministic() {
    let schema1 = collect_schema(vec![core_schema()]).unwrap();
    let schema2 = collect_schema(vec![core_schema()]).unwrap();
    assert_eq!(schema_hash(&schema1), schema_hash(&schema2));
}

#[test]
fn schema_hash_changes_when_column_added() {
    let schema1 = collect_schema(vec![core_schema()]).unwrap();
    let mut modified_core = core_schema();
    modified_core[0]
        .columns
        .push(ColumnDef::new("extra_col", ColumnType::Varchar).nullable());
    let schema2 = collect_schema(vec![modified_core]).unwrap();
    assert_ne!(schema_hash(&schema1), schema_hash(&schema2));
}

// -- DDL generation tests --

#[test]
fn postgres_ddl_core_tables() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_sessions"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_audit_log"));
    assert!(ddl.contains("id UUID PRIMARY KEY DEFAULT gen_random_uuid()"));
    assert!(ddl.contains("REFERENCES yauth_users(id) ON DELETE CASCADE"));
    assert!(ddl.contains("REFERENCES yauth_users(id) ON DELETE SET NULL"));
}

// -- Full schema tests --

#[test]
fn full_schema_topological_order() {
    let schema = collect_schema(vec![
        core_schema(),
        plugin_schemas::email_password_schema(),
        plugin_schemas::passkey_schema(),
        plugin_schemas::mfa_schema(),
        plugin_schemas::oauth_schema(),
        plugin_schemas::bearer_schema(),
        plugin_schemas::api_key_schema(),
        plugin_schemas::magic_link_schema(),
        plugin_schemas::oauth2_server_schema(),
        plugin_schemas::account_lockout_schema(),
        plugin_schemas::webhooks_schema(),
        plugin_schemas::oidc_schema(),
    ])
    .unwrap();

    let positions: std::collections::HashMap<&str, usize> = schema
        .tables
        .iter()
        .enumerate()
        .map(|(i, t)| (t.name.as_str(), i))
        .collect();

    assert_eq!(positions["yauth_users"], 0, "yauth_users should be first");
    for table in &schema.tables {
        for dep in table.dependencies() {
            assert!(
                positions[table.name.as_str()] > positions[dep],
                "Table '{}' (pos {}) should come after '{}' (pos {})",
                table.name,
                positions[table.name.as_str()],
                dep,
                positions[dep],
            );
        }
    }

    assert!(positions["yauth_webhook_deliveries"] > positions["yauth_webhooks"]);
}

#[test]
fn generated_ddl_has_all_tables() {
    let schema = collect_schema(vec![
        core_schema(),
        plugin_schemas::email_password_schema(),
        plugin_schemas::passkey_schema(),
        plugin_schemas::mfa_schema(),
        plugin_schemas::oauth_schema(),
        plugin_schemas::bearer_schema(),
        plugin_schemas::api_key_schema(),
        plugin_schemas::magic_link_schema(),
        plugin_schemas::oauth2_server_schema(),
        plugin_schemas::account_lockout_schema(),
        plugin_schemas::webhooks_schema(),
        plugin_schemas::oidc_schema(),
    ])
    .unwrap();
    let ddl = generate_postgres_ddl(&schema);

    let expected_tables = [
        "yauth_users",
        "yauth_sessions",
        "yauth_audit_log",
        "yauth_challenges",
        "yauth_rate_limits",
        "yauth_revocations",
        "yauth_passwords",
        "yauth_email_verifications",
        "yauth_password_resets",
        "yauth_webauthn_credentials",
        "yauth_totp_secrets",
        "yauth_backup_codes",
        "yauth_oauth_accounts",
        "yauth_oauth_states",
        "yauth_refresh_tokens",
        "yauth_api_keys",
        "yauth_magic_links",
        "yauth_oauth2_clients",
        "yauth_authorization_codes",
        "yauth_consents",
        "yauth_device_codes",
        "yauth_account_locks",
        "yauth_unlock_tokens",
        "yauth_webhooks",
        "yauth_webhook_deliveries",
        "yauth_oidc_nonces",
    ];

    for table in &expected_tables {
        assert!(
            ddl.contains(&format!("CREATE TABLE IF NOT EXISTS {}", table)),
            "Missing table: {}",
            table
        );
    }

    let create_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(create_count, expected_tables.len());
}

// -- SQLite DDL tests --

#[test]
fn sqlite_ddl_has_pragma_foreign_keys() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        ddl.starts_with("PRAGMA foreign_keys = ON;"),
        "SQLite DDL must start with PRAGMA foreign_keys = ON"
    );
}

#[test]
fn sqlite_ddl_core_tables() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_sessions"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_audit_log"));
}

#[test]
fn sqlite_ddl_type_mappings() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        ddl.contains("id TEXT PRIMARY KEY"),
        "UUID should map to TEXT in SQLite. DDL:\n{ddl}"
    );
    assert!(
        ddl.contains("email_verified INTEGER"),
        "BOOLEAN should map to INTEGER in SQLite. DDL:\n{ddl}"
    );
    assert!(
        ddl.contains("created_at TEXT"),
        "DateTime should map to TEXT in SQLite. DDL:\n{ddl}"
    );
}

#[test]
fn sqlite_ddl_no_gen_random_uuid() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        !ddl.contains("gen_random_uuid()"),
        "SQLite DDL should not contain gen_random_uuid()"
    );
}

#[test]
fn sqlite_ddl_now_becomes_current_timestamp() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        !ddl.contains("now()"),
        "SQLite DDL should not contain now()"
    );
    assert!(
        ddl.contains("CURRENT_TIMESTAMP"),
        "SQLite DDL should contain CURRENT_TIMESTAMP"
    );
}

#[test]
fn sqlite_ddl_has_all_tables() {
    let schema = collect_schema(vec![
        core_schema(),
        plugin_schemas::email_password_schema(),
        plugin_schemas::passkey_schema(),
        plugin_schemas::mfa_schema(),
        plugin_schemas::oauth_schema(),
        plugin_schemas::bearer_schema(),
        plugin_schemas::api_key_schema(),
        plugin_schemas::magic_link_schema(),
        plugin_schemas::oauth2_server_schema(),
        plugin_schemas::account_lockout_schema(),
        plugin_schemas::webhooks_schema(),
        plugin_schemas::oidc_schema(),
    ])
    .unwrap();
    let ddl = generate_sqlite_ddl(&schema);

    let create_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(create_count, 26);
}

#[test]
fn sqlite_ddl_json_maps_to_text() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        !ddl.contains("JSONB"),
        "SQLite DDL should not contain JSONB"
    );
    assert!(
        !ddl.contains("JSON"),
        "SQLite DDL should not contain JSON type"
    );
}

#[test]
fn sqlite_ddl_foreign_keys() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(ddl.contains("REFERENCES yauth_users(id) ON DELETE CASCADE"));
}

// -- MySQL DDL tests --

#[test]
fn mysql_ddl_core_tables() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_users`"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_sessions`"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_audit_log`"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_challenges`"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_rate_limits`"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS `yauth_revocations`"));
}

#[test]
fn mysql_ddl_engine_innodb() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    let engine_count = ddl.matches("ENGINE=InnoDB").count();
    let table_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(
        engine_count, table_count,
        "Every CREATE TABLE should have ENGINE=InnoDB"
    );
}

#[test]
fn mysql_ddl_type_mappings() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(
        ddl.contains("`id` CHAR(36) PRIMARY KEY"),
        "UUID should map to CHAR(36) in MySQL. DDL:\n{ddl}"
    );
    assert!(
        ddl.contains("`email_verified` TINYINT(1)"),
        "BOOLEAN should map to TINYINT(1) in MySQL. DDL:\n{ddl}"
    );
    assert!(
        ddl.contains("`created_at` DATETIME"),
        "DateTime should map to DATETIME in MySQL. DDL:\n{ddl}"
    );
}

#[test]
fn mysql_ddl_no_gen_random_uuid() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(
        !ddl.contains("gen_random_uuid()"),
        "MySQL DDL should not contain gen_random_uuid()"
    );
}

#[test]
fn mysql_ddl_now_becomes_current_timestamp() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(
        !ddl.contains("now()"),
        "MySQL DDL should not contain lowercase now()"
    );
    assert!(
        ddl.contains("CURRENT_TIMESTAMP"),
        "MySQL DDL should contain CURRENT_TIMESTAMP"
    );
}

#[test]
fn mysql_ddl_json_type() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(!ddl.contains("JSONB"), "MySQL DDL should not contain JSONB");
    assert!(
        ddl.contains("`metadata` JSON"),
        "MySQL DDL should use JSON type for metadata column. DDL:\n{ddl}"
    );
}

#[test]
fn mysql_ddl_varchar_has_length() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(
        ddl.contains("VARCHAR(255)"),
        "Bare VARCHAR should map to VARCHAR(255) in MySQL. DDL:\n{ddl}"
    );
}

#[test]
fn mysql_ddl_has_all_tables() {
    let schema = collect_schema(vec![
        core_schema(),
        plugin_schemas::email_password_schema(),
        plugin_schemas::passkey_schema(),
        plugin_schemas::mfa_schema(),
        plugin_schemas::oauth_schema(),
        plugin_schemas::bearer_schema(),
        plugin_schemas::api_key_schema(),
        plugin_schemas::magic_link_schema(),
        plugin_schemas::oauth2_server_schema(),
        plugin_schemas::account_lockout_schema(),
        plugin_schemas::webhooks_schema(),
        plugin_schemas::oidc_schema(),
    ])
    .unwrap();
    let ddl = generate_mysql_ddl(&schema);

    let create_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(create_count, 26);
}

// -- Plugin lookup tests --

#[test]
fn plugin_schema_by_name_returns_correct_schemas() {
    for name in ALL_PLUGINS {
        assert!(
            plugin_schema_by_name(name).is_some(),
            "plugin_schema_by_name should return Some for '{name}'"
        );
    }
    assert!(plugin_schema_by_name("nonexistent").is_none());
}

#[test]
fn collect_schema_for_plugins_with_default_prefix() {
    let schema =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "yauth_")
            .unwrap();
    assert!(schema.table("yauth_users").is_some());
    assert!(schema.table("yauth_passwords").is_some());
    assert!(schema.table("yauth_totp_secrets").is_some());
}

#[test]
fn collect_schema_for_plugins_with_custom_prefix() {
    let schema = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
    assert!(schema.table("auth_users").is_some());
    assert!(schema.table("auth_passwords").is_some());
    assert!(schema.table("yauth_users").is_none());
}

#[test]
fn custom_prefix_applies_to_fk_references() {
    let schema = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
    let ddl = generate_postgres_ddl(&schema);
    assert!(ddl.contains("REFERENCES auth_users(id)"));
    assert!(!ddl.contains("REFERENCES yauth_users"));
}

#[test]
fn unknown_plugin_returns_error() {
    let result = collect_schema_for_plugins(&["nonexistent".to_string()], "yauth_");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown plugin"));
}

// -- Diff engine: add MFA plugin across all dialects --

#[test]
fn diff_add_mfa_to_email_password_postgres() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "yauth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Postgres);

    // Up should create exactly the two MFA tables
    assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_totp_secrets"));
    assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_backup_codes"));
    assert_eq!(up.matches("CREATE TABLE IF NOT EXISTS").count(), 2);
    // Down should drop them
    assert!(down.contains("DROP TABLE IF EXISTS yauth_totp_secrets CASCADE"));
    assert!(down.contains("DROP TABLE IF EXISTS yauth_backup_codes CASCADE"));
}

#[test]
fn diff_add_mfa_to_email_password_mysql() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "yauth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Mysql);

    assert!(up.contains("CREATE TABLE IF NOT EXISTS `yauth_totp_secrets`"));
    assert!(up.contains("CREATE TABLE IF NOT EXISTS `yauth_backup_codes`"));
    assert_eq!(up.matches("CREATE TABLE IF NOT EXISTS").count(), 2);
    assert!(up.contains("ENGINE=InnoDB"));
    assert!(down.contains("DROP TABLE IF EXISTS `yauth_totp_secrets`"));
    assert!(down.contains("DROP TABLE IF EXISTS `yauth_backup_codes`"));
}

#[test]
fn diff_add_mfa_to_email_password_sqlite() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "yauth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Sqlite);

    assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_totp_secrets"));
    assert!(up.contains("CREATE TABLE IF NOT EXISTS yauth_backup_codes"));
    assert_eq!(up.matches("CREATE TABLE IF NOT EXISTS").count(), 2);
    assert!(!up.contains("PRAGMA")); // Individual creates shouldn't have PRAGMA
    assert!(down.contains("DROP TABLE IF EXISTS yauth_totp_secrets"));
    assert!(down.contains("DROP TABLE IF EXISTS yauth_backup_codes"));
}

// -- Diff engine: remove passkey plugin across all dialects --

#[test]
fn diff_remove_passkey_from_email_password_plus_passkey_postgres() {
    let from = collect_schema_for_plugins(
        &["email-password".to_string(), "passkey".to_string()],
        "yauth_",
    )
    .unwrap();
    let to = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Postgres);

    assert!(up.contains("DROP TABLE IF EXISTS yauth_webauthn_credentials CASCADE"));
    assert!(!up.contains("CREATE TABLE"));
    // Down should recreate the table
    assert!(down.contains("CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials"));
}

#[test]
fn diff_remove_passkey_from_email_password_plus_passkey_mysql() {
    let from = collect_schema_for_plugins(
        &["email-password".to_string(), "passkey".to_string()],
        "yauth_",
    )
    .unwrap();
    let to = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Mysql);

    assert!(up.contains("DROP TABLE IF EXISTS `yauth_webauthn_credentials`"));
    assert!(!up.contains("CREATE TABLE"));
    assert!(down.contains("CREATE TABLE IF NOT EXISTS `yauth_webauthn_credentials`"));
}

#[test]
fn diff_remove_passkey_from_email_password_plus_passkey_sqlite() {
    let from = collect_schema_for_plugins(
        &["email-password".to_string(), "passkey".to_string()],
        "yauth_",
    )
    .unwrap();
    let to = collect_schema_for_plugins(&["email-password".to_string()], "yauth_").unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Sqlite);

    assert!(up.contains("DROP TABLE IF EXISTS yauth_webauthn_credentials"));
    assert!(!up.contains("CREATE TABLE"));
    assert!(down.contains("CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials"));
}

// -- Diff engine: custom prefix --

#[test]
fn diff_custom_prefix_postgres() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "auth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, down) = diff::render_changes_sql(&changes, Dialect::Postgres);

    // All references should use auth_ not yauth_
    assert!(up.contains("auth_totp_secrets"));
    assert!(up.contains("auth_backup_codes"));
    assert!(!up.contains("yauth_"));
    assert!(up.contains("REFERENCES auth_users(id)"));
    assert!(down.contains("auth_totp_secrets"));
    assert!(!down.contains("yauth_"));
}

#[test]
fn diff_custom_prefix_mysql() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "auth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, _down) = diff::render_changes_sql(&changes, Dialect::Mysql);

    assert!(up.contains("`auth_totp_secrets`"));
    assert!(up.contains("`auth_backup_codes`"));
    assert!(!up.contains("yauth_"));
}

#[test]
fn diff_custom_prefix_sqlite() {
    let from = collect_schema_for_plugins(&["email-password".to_string()], "auth_").unwrap();
    let to =
        collect_schema_for_plugins(&["email-password".to_string(), "mfa".to_string()], "auth_")
            .unwrap();
    let changes = diff::schema_diff(&from, &to);
    let (up, _down) = diff::render_changes_sql(&changes, Dialect::Sqlite);

    assert!(up.contains("auth_totp_secrets"));
    assert!(up.contains("auth_backup_codes"));
    assert!(!up.contains("yauth_"));
}

// -- Config tests --

#[test]
fn config_roundtrip() {
    let config = config::YAuthConfig::new(
        Orm::Diesel,
        "postgres",
        vec!["email-password".to_string(), "mfa".to_string()],
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("yauth.toml");
    config.save(&path).unwrap();

    let loaded = config::YAuthConfig::load(&path).unwrap();
    assert_eq!(loaded.migration.orm, Orm::Diesel);
    assert_eq!(loaded.migration.dialect, "postgres");
    assert_eq!(loaded.plugins.enabled, vec!["email-password", "mfa"]);
    assert_eq!(loaded.migration.table_prefix, "yauth_");
}

#[test]
fn config_rejects_bad_orm_in_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("yauth.toml");
    std::fs::write(
        &path,
        r#"
[migration]
orm = "badorm"
dialect = "postgres"
table_prefix = "yauth_"

[plugins]
enabled = ["email-password"]
"#,
    )
    .unwrap();
    assert!(config::YAuthConfig::load(&path).is_err());
}

#[test]
fn config_validates_dialect() {
    let config = config::YAuthConfig::new(
        Orm::Diesel,
        "baddialect",
        vec!["email-password".to_string()],
    );
    assert!(config.validate().is_err());
}

#[test]
fn config_validates_plugins() {
    let config = config::YAuthConfig::new(Orm::Diesel, "postgres", vec!["nonexistent".to_string()]);
    assert!(config.validate().is_err());
}

// -- Dialect parsing tests --

#[test]
fn dialect_from_str() {
    assert_eq!("postgres".parse::<Dialect>().unwrap(), Dialect::Postgres);
    assert_eq!("postgresql".parse::<Dialect>().unwrap(), Dialect::Postgres);
    assert_eq!("pg".parse::<Dialect>().unwrap(), Dialect::Postgres);
    assert_eq!("sqlite".parse::<Dialect>().unwrap(), Dialect::Sqlite);
    assert_eq!("mysql".parse::<Dialect>().unwrap(), Dialect::Mysql);
    assert_eq!("mariadb".parse::<Dialect>().unwrap(), Dialect::Mysql);
    assert!("baddb".parse::<Dialect>().is_err());
}
