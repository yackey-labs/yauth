//! Unit tests for the declarative schema system.

use super::*;

/// Normalize a column definition line for semantic comparison.
/// Sorts constraint keywords so "NOT NULL UNIQUE" == "UNIQUE NOT NULL"
/// and "NOT NULL DEFAULT false" == "DEFAULT false NOT NULL".
///
/// We only need to handle the cases present in yauth's existing SQL:
/// - PRIMARY KEY DEFAULT ...
/// - [UNIQUE] [NOT NULL] [DEFAULT ...] [REFERENCES ...]
fn normalize_col_line(line: &str) -> String {
    let line = line.trim().trim_end_matches(',');
    // Split into name + type + constraints
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return line.to_string();
    }

    // Reconstruct: keep name and type, then sort constraint parts
    let name = parts[0];

    // Find the type (may be multi-word for VARCHAR(64))
    // The type is always the second token
    let col_type = parts[1];
    let type_end = 2;

    let constraints_str = parts[type_end..].join(" ");

    // Extract constraint parts in a canonical order
    let has_pk = constraints_str.contains("PRIMARY KEY");
    let has_not_null = constraints_str.contains("NOT NULL");
    let has_unique = constraints_str.contains("UNIQUE");

    // Extract DEFAULT value
    let default_val = if let Some(idx) = constraints_str.find("DEFAULT ") {
        let rest = &constraints_str[idx + 8..];
        // Default value can be a function call like gen_random_uuid() or now()
        // or a literal like false, 'user', 0, 5
        let end = if rest.starts_with('\'') {
            // Quoted string: find closing quote
            rest[1..].find('\'').map(|i| i + 2).unwrap_or(rest.len())
        } else if rest.contains('(') {
            // Function call: find closing paren
            rest.find(')').map(|i| i + 1).unwrap_or(rest.len())
        } else {
            // Simple value
            rest.find(' ').unwrap_or(rest.len())
        };
        Some(&rest[..end])
    } else {
        None
    };

    // Extract REFERENCES clause
    let fk_clause = if let Some(idx) = constraints_str.find("REFERENCES ") {
        Some(&constraints_str[idx..])
    } else {
        None
    };

    // For FK clause, we need to strip UNIQUE from the end if it was there
    let fk_clause = fk_clause.map(|fk| fk.trim_end_matches("UNIQUE").trim_end());

    // Rebuild in canonical order:
    // name TYPE [PRIMARY KEY] [DEFAULT value] [REFERENCES ...] [NOT NULL] [UNIQUE]
    let mut result = format!("{} {}", name, col_type);
    if has_pk {
        result.push_str(" PRIMARY KEY");
    }
    if let Some(def) = default_val {
        result.push_str(&format!(" DEFAULT {}", def));
    }
    if let Some(fk) = fk_clause {
        result.push_str(&format!(
            " REFERENCES {}",
            fk.trim_start_matches("REFERENCES ")
        ));
    }
    if has_not_null && !has_pk {
        result.push_str(" NOT NULL");
    }
    if has_unique && !has_pk {
        result.push_str(" UNIQUE");
    }

    result
}

/// Extract individual CREATE TABLE blocks from SQL and normalize them
/// for semantic comparison. Returns a map of table_name -> normalized columns.
fn extract_tables(sql: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut tables = std::collections::HashMap::new();
    let clean = sql
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");

    for chunk in clean.split("CREATE TABLE IF NOT EXISTS ").skip(1) {
        let table_name = chunk.split_whitespace().next().unwrap().to_string();
        // Get content between ( and );
        if let Some(paren_start) = chunk.find('(') {
            if let Some(paren_end) = chunk.rfind(");") {
                let body = &chunk[paren_start + 1..paren_end];
                let cols: Vec<String> = body
                    .split('\n')
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .map(|l| normalize_col_line(l))
                    .collect();
                tables.insert(table_name, cols);
            }
        }
    }
    tables
}

/// Assert that two SQL DDL strings produce the same tables with the same columns.
fn assert_tables_match(generated: &str, expected: &str, context: &str) {
    let gen_tables = extract_tables(generated);
    let exp_tables = extract_tables(expected);

    for (table_name, exp_cols) in &exp_tables {
        let gen_cols = gen_tables.get(table_name).unwrap_or_else(|| {
            panic!(
                "{}: Missing table '{}' in generated DDL",
                context, table_name
            )
        });

        assert_eq!(
            gen_cols.len(),
            exp_cols.len(),
            "{}: Table '{}' has {} columns in generated DDL but {} in expected\nGenerated: {:?}\nExpected: {:?}",
            context,
            table_name,
            gen_cols.len(),
            exp_cols.len(),
            gen_cols,
            exp_cols,
        );

        for (i, (got, exp)) in gen_cols.iter().zip(exp_cols.iter()).enumerate() {
            assert_eq!(
                got, exp,
                "{}: Table '{}' column {} differs.\nGenerated: {}\nExpected:  {}",
                context, table_name, i, got, exp,
            );
        }
    }
}

// ── Basic structure tests ───────────────────────────────────────────

#[test]
fn core_schema_has_three_tables() {
    let tables = core_schema();
    assert_eq!(tables.len(), 3);
    assert_eq!(tables[0].name, "yauth_users");
    assert_eq!(tables[1].name, "yauth_sessions");
    assert_eq!(tables[2].name, "yauth_audit_log");
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
    // Core schema declares [users, sessions, audit_log]
    // Sessions and audit_log both depend only on users.
    // The sort should preserve the input order: sessions before audit_log.
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
        .push(types::ColumnDef::new("extra_col", types::ColumnType::Varchar).nullable());
    let schema2 = collect_schema(vec![modified_core]).unwrap();
    assert_ne!(schema_hash(&schema1), schema_hash(&schema2));
}

// ── DDL generation tests ───────────────────────────────────────────

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

// ── Migration comparison tests ──────────────────────────────────────
//
// Each test verifies the generated DDL produces semantically identical
// table structures to the existing SQL migration files.

#[test]
fn generated_ddl_matches_core_migration() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000001_core/up.sql");
    assert_tables_match(&ddl, expected, "core");
}

#[test]
fn generated_ddl_matches_email_password_migration() {
    let schema =
        collect_schema(vec![core_schema(), plugin_schemas::email_password_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000002_email_password/up.sql");
    assert_tables_match(&ddl, expected, "email_password");
}

#[test]
fn generated_ddl_matches_passkey_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::passkey_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000003_passkey/up.sql");
    assert_tables_match(&ddl, expected, "passkey");
}

#[test]
fn generated_ddl_matches_mfa_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::mfa_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000004_mfa/up.sql");
    assert_tables_match(&ddl, expected, "mfa");
}

#[test]
fn generated_ddl_matches_oauth_migration() {
    // OAuth schema includes the oauth_token_refresh columns (migration 009) merged in.
    // So yauth_oauth_accounts has 9 columns (7 base + expires_at + updated_at).
    // We verify:
    // 1. yauth_oauth_states matches the base migration exactly
    // 2. yauth_oauth_accounts includes all base columns plus the merged columns
    let schema = collect_schema(vec![core_schema(), plugin_schemas::oauth_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected_base = include_str!("../../diesel_migrations/00000000000005_oauth/up.sql");

    // oauth_states table should match exactly
    let gen_tables = extract_tables(&ddl);
    let exp_tables = extract_tables(expected_base);
    let gen_states = gen_tables
        .get("yauth_oauth_states")
        .expect("Missing yauth_oauth_states");
    let exp_states = exp_tables
        .get("yauth_oauth_states")
        .expect("Missing expected yauth_oauth_states");
    assert_eq!(gen_states, exp_states, "oauth_states mismatch");

    // oauth_accounts: verify all base columns are present
    let gen_accounts = gen_tables
        .get("yauth_oauth_accounts")
        .expect("Missing yauth_oauth_accounts");
    let exp_accounts = exp_tables
        .get("yauth_oauth_accounts")
        .expect("Missing expected yauth_oauth_accounts");
    for exp_col in exp_accounts {
        assert!(
            gen_accounts.contains(exp_col),
            "Missing base column in oauth_accounts: {}",
            exp_col
        );
    }
    // Plus the merged columns from migration 009
    assert!(
        ddl.contains("expires_at TIMESTAMPTZ"),
        "Missing expires_at on oauth_accounts"
    );
    assert!(
        ddl.contains("updated_at TIMESTAMPTZ"),
        "Missing updated_at on oauth_accounts"
    );
    assert_eq!(
        gen_accounts.len(),
        9,
        "Expected 9 columns on oauth_accounts (7 base + 2 from migration 009)"
    );
}

#[test]
fn generated_ddl_matches_bearer_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::bearer_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000006_bearer/up.sql");
    assert_tables_match(&ddl, expected, "bearer");
}

#[test]
fn generated_ddl_matches_api_key_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::api_key_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000007_api_key/up.sql");
    assert_tables_match(&ddl, expected, "api_key");
}

#[test]
fn generated_ddl_matches_magic_link_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::magic_link_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000008_magic_link/up.sql");
    assert_tables_match(&ddl, expected, "magic_link");
}

#[test]
fn generated_ddl_matches_oauth2_server_migration() {
    let schema =
        collect_schema(vec![core_schema(), plugin_schemas::oauth2_server_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000010_oauth2_server/up.sql");
    assert_tables_match(&ddl, expected, "oauth2_server");
}

#[test]
fn generated_ddl_matches_device_authorization_migration() {
    let schema =
        collect_schema(vec![core_schema(), plugin_schemas::oauth2_server_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected =
        include_str!("../../diesel_migrations/00000000000011_device_authorization/up.sql");
    assert_tables_match(&ddl, expected, "device_authorization");
}

#[test]
fn generated_ddl_matches_account_lockout_migration() {
    let schema = collect_schema(vec![
        core_schema(),
        plugin_schemas::account_lockout_schema(),
    ])
    .unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000012_account_lockout/up.sql");
    assert_tables_match(&ddl, expected, "account_lockout");
}

#[test]
fn generated_ddl_matches_webhooks_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::webhooks_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000014_webhooks/up.sql");
    assert_tables_match(&ddl, expected, "webhooks");
}

#[test]
fn generated_ddl_matches_oidc_migration() {
    let schema = collect_schema(vec![core_schema(), plugin_schemas::oidc_schema()]).unwrap();
    let ddl = generate_postgres_ddl(&schema);
    let expected = include_str!("../../diesel_migrations/00000000000015_oidc/up.sql");
    assert_tables_match(&ddl, expected, "oidc");
}

// ── Full schema tests ───────────────────────────────────────────────

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
        .map(|(i, t)| (t.name, i))
        .collect();

    // All tables referencing yauth_users must come after it
    assert_eq!(positions["yauth_users"], 0, "yauth_users should be first");
    for table in &schema.tables {
        for dep in table.dependencies() {
            assert!(
                positions[table.name] > positions[dep],
                "Table '{}' (pos {}) should come after '{}' (pos {})",
                table.name,
                positions[table.name],
                dep,
                positions[dep],
            );
        }
    }

    // webhook_deliveries after webhooks
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

// ── SQLite DDL generation tests ───────────────────────────────────────

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
    // UUID -> TEXT
    assert!(
        ddl.contains("id TEXT PRIMARY KEY"),
        "UUID should map to TEXT in SQLite. DDL:\n{ddl}"
    );
    // BOOLEAN -> INTEGER
    assert!(
        ddl.contains("email_verified INTEGER"),
        "BOOLEAN should map to INTEGER in SQLite. DDL:\n{ddl}"
    );
    // DateTime -> TEXT
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
    // The core schema uses now() as default for created_at/updated_at on users.
    // In SQLite this becomes CURRENT_TIMESTAMP.
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

    let expected_tables = [
        "yauth_users",
        "yauth_sessions",
        "yauth_audit_log",
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
            "SQLite DDL missing table: {}",
            table
        );
    }

    let create_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(create_count, expected_tables.len());
}

#[test]
fn sqlite_ddl_json_maps_to_text() {
    // The audit_log table has a JSONB column (metadata). In SQLite it should be TEXT.
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        !ddl.contains("JSONB"),
        "SQLite DDL should not contain JSONB"
    );
    assert!(
        !ddl.contains("JSON"),
        "SQLite DDL should not contain JSON type (it should be TEXT)"
    );
}

#[test]
fn sqlite_ddl_foreign_keys() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_sqlite_ddl(&schema);
    assert!(
        ddl.contains("REFERENCES yauth_users(id) ON DELETE CASCADE"),
        "SQLite DDL should contain FK references"
    );
}

// ── MySQL DDL generation tests ─────────────────────────────────────────

#[test]
fn mysql_ddl_core_tables() {
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_sessions"));
    assert!(ddl.contains("CREATE TABLE IF NOT EXISTS yauth_audit_log"));
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
    // UUID -> CHAR(36)
    assert!(
        ddl.contains("id CHAR(36) PRIMARY KEY"),
        "UUID should map to CHAR(36) in MySQL. DDL:\n{ddl}"
    );
    // BOOLEAN -> TINYINT(1)
    assert!(
        ddl.contains("email_verified TINYINT(1)"),
        "BOOLEAN should map to TINYINT(1) in MySQL. DDL:\n{ddl}"
    );
    // DateTime -> DATETIME
    assert!(
        ddl.contains("created_at DATETIME"),
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
    // The audit_log table has a JSONB column (metadata). In MySQL it should be JSON.
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    assert!(!ddl.contains("JSONB"), "MySQL DDL should not contain JSONB");
    // JSON should appear for the metadata column
    assert!(
        ddl.contains("metadata JSON"),
        "MySQL DDL should use JSON type for metadata column. DDL:\n{ddl}"
    );
}

#[test]
fn mysql_ddl_varchar_has_length() {
    // In MySQL, bare VARCHAR needs a length. We default to VARCHAR(255).
    let schema = collect_schema(vec![core_schema()]).unwrap();
    let ddl = generate_mysql_ddl(&schema);
    // email column is Varchar type -> should become VARCHAR(255)
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

    let expected_tables = [
        "yauth_users",
        "yauth_sessions",
        "yauth_audit_log",
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
            "MySQL DDL missing table: {}",
            table
        );
    }

    let create_count = ddl.matches("CREATE TABLE IF NOT EXISTS").count();
    assert_eq!(create_count, expected_tables.len());
}
