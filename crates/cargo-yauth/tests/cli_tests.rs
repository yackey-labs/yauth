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
