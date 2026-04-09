use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn cargo_yauth() -> Command {
    Command::cargo_bin("cargo-yauth").unwrap()
}

#[test]
fn init_non_interactive_diesel_postgres() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"))
        .stdout(predicate::str::contains("up.sql"));

    // Verify config was created
    assert!(config_path.exists());
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("diesel"));
    assert!(config_content.contains("postgres"));
    assert!(config_content.contains("email-password"));
    assert!(config_content.contains("passkey"));

    // Verify migration files were created
    let migrations_dir = dir.path().join("migrations");
    assert!(migrations_dir.exists());
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_dir())
        .collect();
    assert!(!entries.is_empty());

    // Check up.sql contains expected SQL
    let migration_dir = &entries[0].path();
    let up_sql = std::fs::read_to_string(migration_dir.join("up.sql")).unwrap();
    assert!(up_sql.contains("CREATE TABLE IF NOT EXISTS yauth_users"));
    assert!(up_sql.contains("CREATE TABLE IF NOT EXISTS yauth_passwords"));
    assert!(up_sql.contains("CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials"));
    assert!(up_sql.contains("UUID PRIMARY KEY"));

    // Check down.sql exists
    let down_sql = std::fs::read_to_string(migration_dir.join("down.sql")).unwrap();
    assert!(down_sql.contains("DROP TABLE"));

    // Check schema.rs was generated for diesel
    let schema_rs = std::fs::read_to_string(migrations_dir.join("schema.rs")).unwrap();
    assert!(schema_rs.contains("diesel::table!"));
    assert!(schema_rs.contains("yauth_users (id)"));
}

#[test]
fn init_non_interactive_sqlx_sqlite() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "sqlite",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    // sqlx produces numbered .sql files
    let migrations_dir = dir.path().join("migrations");
    assert!(migrations_dir.exists());
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1);

    let filename = entries[0].file_name().to_string_lossy().to_string();
    assert!(filename.ends_with(".sql"));
    assert!(filename.starts_with("00000001_"));

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    // SQLite should use TEXT for UUIDs, not UUID
    assert!(!content.contains("UUID "));
    assert!(content.contains("TEXT PRIMARY KEY"));
}

#[test]
fn init_with_custom_prefix() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
            "--prefix",
            "auth_",
        ])
        .assert()
        .success();

    let migrations_dir = dir.path().join("migrations");
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_dir())
        .collect();
    let up_sql = std::fs::read_to_string(entries[0].path().join("up.sql")).unwrap();
    assert!(up_sql.contains("auth_users"));
    assert!(up_sql.contains("auth_passwords"));
    assert!(up_sql.contains("REFERENCES auth_users(id)"));
    assert!(!up_sql.contains("yauth_"));

    // Check schema.rs uses custom prefix
    let schema_rs = std::fs::read_to_string(migrations_dir.join("schema.rs")).unwrap();
    assert!(schema_rs.contains("auth_users (id)"));
    assert!(!schema_rs.contains("yauth_"));
}

#[test]
fn init_with_custom_config_path() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.dev.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "sqlite",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    assert!(config_path.exists());
}

#[test]
fn init_fails_if_config_exists() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");
    std::fs::write(&config_path, "already exists").unwrap();

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn add_plugin_creates_incremental_migration() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // First, init
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    // Then add mfa
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "add-plugin",
            "mfa",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("yauth_totp_secrets"));

    // Verify config was updated
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("mfa"));

    // Verify new migration was created (should now be 2 migration dirs)
    let migrations_dir = dir.path().join("migrations");
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_dir())
        .collect();
    assert_eq!(entries.len(), 2);
}

#[test]
fn add_plugin_fails_for_unknown_plugin() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "add-plugin",
            "nonexistent",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown plugin"));
}

#[test]
fn remove_plugin_creates_drop_migration() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey",
        ])
        .assert()
        .success();

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "remove-plugin",
            "passkey",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("DROP TABLE"));

    // Verify config was updated
    let config_content = std::fs::read_to_string(&config_path).unwrap();
    assert!(!config_content.contains("passkey"));
    assert!(config_content.contains("email-password"));
}

#[test]
fn status_shows_config() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,mfa",
        ])
        .assert()
        .success();

    cargo_yauth()
        .current_dir(dir.path())
        .args(["yauth", "-f", config_path.to_str().unwrap(), "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("diesel"))
        .stdout(predicate::str::contains("postgres"))
        .stdout(predicate::str::contains("email-password"))
        .stdout(predicate::str::contains("mfa"))
        .stdout(predicate::str::contains("passkey")); // should be listed as available
}

#[test]
fn init_mysql_produces_correct_ddl() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "mysql",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    let migrations_dir = dir.path().join("migrations");
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_dir())
        .collect();
    let up_sql = std::fs::read_to_string(entries[0].path().join("up.sql")).unwrap();
    assert!(up_sql.contains("ENGINE=InnoDB"));
    assert!(up_sql.contains("CHAR(36)"));
    assert!(up_sql.contains("TINYINT(1)"));

    // Check schema.rs uses MySQL diesel types
    let schema_rs = std::fs::read_to_string(migrations_dir.join("schema.rs")).unwrap();
    assert!(schema_rs.contains("diesel::table!"));
    assert!(schema_rs.contains("-> Datetime,"));
}

// ──────────────────────────────────────────────
// sqlx query file generation tests
// ──────────────────────────────────────────────

#[test]
fn init_sqlx_postgres_generates_query_files() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey,mfa",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("query files"));

    // Verify queries/ directory exists
    let queries_dir = dir.path().join("queries");
    assert!(queries_dir.exists(), "queries/ directory should exist");

    // Count SQL files
    let query_files: Vec<_> = std::fs::read_dir(&queries_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".sql"))
        .collect();
    assert!(
        query_files.len() > 20,
        "Should have 20+ query files, got {}",
        query_files.len()
    );

    // Core queries should exist
    assert!(queries_dir.join("user_find_by_id.sql").exists());
    assert!(queries_dir.join("user_find_by_email.sql").exists());
    assert!(queries_dir.join("user_create.sql").exists());
    assert!(queries_dir.join("session_create.sql").exists());
    assert!(queries_dir.join("session_validate.sql").exists());
    assert!(queries_dir.join("audit_create.sql").exists());
    assert!(queries_dir.join("rate_limit_check.sql").exists());

    // Plugin queries should exist
    assert!(queries_dir.join("password_find_by_user.sql").exists());
    assert!(queries_dir.join("password_upsert.sql").exists());
    assert!(queries_dir.join("passkey_find_by_user.sql").exists());
    assert!(queries_dir.join("passkey_create.sql").exists());
    assert!(queries_dir.join("totp_find_by_user.sql").exists());
    assert!(queries_dir.join("backup_code_create.sql").exists());

    // Verify query content: postgres should use $1 params
    let user_create = std::fs::read_to_string(queries_dir.join("user_create.sql")).unwrap();
    assert!(user_create.contains("$1"), "Postgres should use $1 params");
    assert!(
        user_create.contains("RETURNING *"),
        "Postgres should use RETURNING *"
    );
    assert!(user_create.starts_with("-- "), "Should start with comment");
    assert!(
        user_create.contains("-- Plugin: core"),
        "Should have plugin line"
    );

    // Verify migration also has table comments
    let migrations_dir = dir.path().join("migrations");
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let migration_sql = std::fs::read_to_string(entries[0].path()).unwrap();
    assert!(
        migration_sql.contains("-- Registered user accounts."),
        "Migration should have table comments"
    );
    assert!(
        migration_sql.contains("-- Hashed passwords."),
        "Migration should have table comments"
    );
}

#[test]
fn init_sqlx_mysql_uses_question_mark_params() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "mysql",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    let user_create = std::fs::read_to_string(queries_dir.join("user_create.sql")).unwrap();
    assert!(user_create.contains("?"), "MySQL should use ? params");
    assert!(
        !user_create.contains("$1"),
        "MySQL should not use $1 params"
    );
    assert!(
        !user_create.contains("RETURNING"),
        "MySQL should not have RETURNING"
    );
}

#[test]
fn init_sqlx_sqlite_uses_question_mark_params() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "sqlite",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    let user_create = std::fs::read_to_string(queries_dir.join("user_create.sql")).unwrap();
    assert!(user_create.contains("?"), "SQLite should use ? params");
    assert!(
        !user_create.contains("$1"),
        "SQLite should not use $1 params"
    );
    assert!(
        user_create.contains("RETURNING *"),
        "SQLite should use RETURNING *"
    );
    assert!(
        user_create.contains("datetime('now')"),
        "SQLite should use datetime('now')"
    );
}

#[test]
fn init_diesel_does_not_generate_query_files() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    assert!(
        !queries_dir.exists(),
        "Diesel should not generate queries/ directory"
    );
}

#[test]
fn add_plugin_sqlx_generates_plugin_query_files() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // Init with email-password
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    let before_count = std::fs::read_dir(&queries_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();

    // Bearer query files should not exist yet
    assert!(!queries_dir.join("refresh_token_create.sql").exists());

    // Add bearer plugin
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "add-plugin",
            "bearer",
        ])
        .assert()
        .success();

    // Bearer query files should now exist
    assert!(queries_dir.join("refresh_token_create.sql").exists());
    assert!(queries_dir.join("refresh_token_find_by_token.sql").exists());
    assert!(queries_dir.join("refresh_token_revoke_family.sql").exists());

    let after_count = std::fs::read_dir(&queries_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();
    assert!(
        after_count > before_count,
        "Should have more query files after add-plugin"
    );
}

#[test]
fn remove_plugin_sqlx_deletes_plugin_query_files() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // Init with email-password + passkey
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    assert!(queries_dir.join("passkey_create.sql").exists());
    assert!(queries_dir.join("passkey_find_by_user.sql").exists());

    // Remove passkey
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "remove-plugin",
            "passkey",
        ])
        .assert()
        .success();

    // Passkey query files should be gone
    assert!(!queries_dir.join("passkey_create.sql").exists());
    assert!(!queries_dir.join("passkey_find_by_user.sql").exists());

    // Core and email-password query files should still exist
    assert!(queries_dir.join("user_find_by_id.sql").exists());
    assert!(queries_dir.join("password_find_by_user.sql").exists());
}

#[test]
fn generate_check_sqlx_passes_on_fresh_output() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // Init
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey",
        ])
        .assert()
        .success();

    // Check should pass immediately after init
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "generate",
            "--check",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("up to date"));
}

#[test]
fn generate_check_sqlx_detects_stale_query_files() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // Init
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password",
        ])
        .assert()
        .success();

    // Tamper with a query file
    let queries_dir = dir.path().join("queries");
    std::fs::write(queries_dir.join("user_create.sql"), "-- tampered").unwrap();

    // Check should fail
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "generate",
            "--check",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("STALE"));
}

#[test]
fn migration_sql_has_table_comments_diesel() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "diesel",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,mfa",
        ])
        .assert()
        .success();

    let migrations_dir = dir.path().join("migrations");
    let entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_dir())
        .collect();
    let up_sql = std::fs::read_to_string(entries[0].path().join("up.sql")).unwrap();
    assert!(
        up_sql.contains("-- Registered user accounts."),
        "Diesel migration should have table comments"
    );
    assert!(
        up_sql.contains("-- Active user sessions."),
        "Diesel migration should have session comment"
    );
    assert!(
        up_sql.contains("-- Hashed passwords."),
        "Diesel migration should have password comment"
    );
    assert!(
        up_sql.contains("-- TOTP secrets for MFA."),
        "Diesel migration should have TOTP comment"
    );
}

#[test]
fn sqlx_query_files_all_have_valid_sql() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("yauth.toml");

    // Enable many plugins
    cargo_yauth()
        .current_dir(dir.path())
        .args([
            "yauth",
            "-f",
            config_path.to_str().unwrap(),
            "init",
            "--orm",
            "sqlx",
            "--dialect",
            "postgres",
            "--plugins",
            "email-password,passkey,mfa,oauth,bearer,api-key,magic-link",
        ])
        .assert()
        .success();

    let queries_dir = dir.path().join("queries");
    let entries: Vec<_> = std::fs::read_dir(&queries_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".sql"))
        .collect();

    assert!(
        entries.len() > 50,
        "Should have 50+ query files with many plugins, got {}",
        entries.len()
    );

    for entry in &entries {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let upper = content.to_uppercase();
        // Every file should have SQL
        assert!(
            upper.contains("SELECT")
                || upper.contains("INSERT")
                || upper.contains("UPDATE")
                || upper.contains("DELETE"),
            "Query {} should contain a SQL keyword",
            entry.file_name().to_string_lossy()
        );
        // Every file should start with a comment
        assert!(
            content.starts_with("-- "),
            "Query {} should start with a comment",
            entry.file_name().to_string_lossy()
        );
        // No template variables
        assert!(
            !content.contains("{{") && !content.contains("}}"),
            "Query {} should not contain template markers",
            entry.file_name().to_string_lossy()
        );
    }
}
