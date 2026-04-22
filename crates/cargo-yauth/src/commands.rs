//! CLI command implementations.

use std::path::Path;

use yauth_migration::config::YAuthConfig;
use yauth_migration::diff::{format_sql_diff, render_changes_sql, schema_diff};
use yauth_migration::generate::{self, write_migration};
use yauth_migration::{Dialect, Orm, collect_schema_for_plugins};

/// `cargo yauth init` -- create yauth.toml and initial migration files.
pub fn init(
    config_path: &Path,
    orm: Option<String>,
    dialect: Option<String>,
    plugins: Option<String>,
    prefix: Option<String>,
    schema: Option<String>,
    migrations_dir: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if config_path.exists() {
        return Err(format!(
            "Config file '{}' already exists. Use `cargo yauth add-plugin` to add plugins.",
            config_path.display()
        )
        .into());
    }

    // Resolve values: use flags if provided, otherwise prompt interactively
    let orm_value = match orm {
        Some(v) => v,
        None => prompt_select("ORM", &["diesel", "sqlx", "seaorm", "toasty"])?,
    };

    let dialect_value = match dialect {
        Some(v) => v,
        None => prompt_select("Dialect", &["postgres", "mysql", "sqlite"])?,
    };

    let plugins_value: Vec<String> = match plugins {
        Some(p) => p.split(',').map(|s| s.trim().to_string()).collect(),
        None => prompt_multi_select("Plugins", yauth_migration::ALL_PLUGINS)?,
    };

    if plugins_value.is_empty() {
        return Err("At least one plugin must be selected.".into());
    }

    let orm: yauth_migration::Orm = orm_value
        .parse()
        .map_err(|e: String| -> Box<dyn std::error::Error> { e.into() })?;
    let mut config = YAuthConfig::new(orm, &dialect_value, plugins_value);

    if let Some(p) = prefix {
        config.migration.table_prefix = p;
    }
    if let Some(s) = schema {
        config.migration.schema = Some(s);
    }
    if let Some(d) = migrations_dir {
        config.migration.migrations_dir = d;
    }

    config.validate().map_err(|e| format!("{e}"))?;

    // Save config
    config.save(config_path)?;
    println!("Created {}", config_path.display());

    // Generate initial migration
    let migration = generate::generate_init(&config)?;
    write_migration(&migration)?;

    for (path, _) in &migration.files {
        println!("  Created {}", path.display());
    }

    // Print guided next-step instructions
    print_next_steps(&config, &migration);
    Ok(())
}

/// `cargo yauth add-plugin <name>` -- add a plugin and generate migration.
pub fn add_plugin(config_path: &Path, plugin_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = YAuthConfig::load(config_path)?;

    // Validate plugin name
    if yauth_migration::plugin_schema_by_name(plugin_name).is_none() {
        return Err(format!(
            "Unknown plugin: '{plugin_name}'\nAvailable plugins: {}",
            yauth_migration::ALL_PLUGINS.join(", ")
        )
        .into());
    }

    if config.plugins.enabled.contains(&plugin_name.to_string()) {
        return Err(format!("Plugin '{plugin_name}' is already enabled.").into());
    }

    let previous_plugins = config.plugins.enabled.clone();
    config.plugins.enabled.push(plugin_name.to_string());

    // Show diff
    let dialect: Dialect = config.migration.dialect.parse().map_err(|e: String| e)?;
    let from = collect_schema_for_plugins(&previous_plugins, &config.migration.table_prefix)?;
    let to = collect_schema_for_plugins(&config.plugins.enabled, &config.migration.table_prefix)?;
    let changes = schema_diff(&from, &to);
    let (up_sql, down_sql) = render_changes_sql(&changes, dialect);

    if !up_sql.trim().is_empty() {
        println!("Schema changes:");
        println!("{}", format_sql_diff("", &up_sql));
    }

    // Generate migration (reuse pre-computed SQL to avoid recomputing the diff)
    let migration = generate::generate_add_plugin(&config, plugin_name, &up_sql, &down_sql)?;
    write_migration(&migration)?;

    for (path, _) in &migration.files {
        println!("  Created {}", path.display());
    }

    // Update config
    config.save(config_path)?;
    println!("Updated {}", config_path.display());

    // Print guided next-step instructions
    print_next_steps(&config, &migration);
    Ok(())
}

/// `cargo yauth remove-plugin <name>` -- remove a plugin and generate migration.
pub fn remove_plugin(
    config_path: &Path,
    plugin_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = YAuthConfig::load(config_path)?;

    if !config.plugins.enabled.contains(&plugin_name.to_string()) {
        return Err(format!("Plugin '{plugin_name}' is not enabled.").into());
    }

    let previous_plugins = config.plugins.enabled.clone();
    config.plugins.enabled.retain(|p| p != plugin_name);

    // Show diff
    let dialect: Dialect = config.migration.dialect.parse().map_err(|e: String| e)?;
    let from = collect_schema_for_plugins(&previous_plugins, &config.migration.table_prefix)?;
    let to = collect_schema_for_plugins(&config.plugins.enabled, &config.migration.table_prefix)?;
    let changes = schema_diff(&from, &to);
    let (up_sql, down_sql) = render_changes_sql(&changes, dialect);

    if !up_sql.trim().is_empty() {
        println!("Schema changes:");
        println!("{}", format_sql_diff("", &up_sql));
    }

    // Generate migration (reuse pre-computed SQL to avoid recomputing the diff)
    let migration = generate::generate_remove_plugin(&config, plugin_name, &up_sql, &down_sql)?;
    write_migration(&migration)?;

    for (path, _) in &migration.files {
        println!("  Created {}", path.display());
    }
    for path in &migration.removed_files {
        println!("  Removed {}", path.display());
    }

    // Update config
    config.save(config_path)?;
    println!("Updated {}", config_path.display());

    // Print guided next-step instructions
    print_next_steps(&config, &migration);
    Ok(())
}

/// `cargo yauth status` -- show current yauth status.
pub fn status(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = YAuthConfig::load(config_path)?;

    println!("yauth configuration: {}", config_path.display());
    println!();
    println!("  ORM:          {}", config.migration.orm);
    println!("  Dialect:      {}", config.migration.dialect);
    println!("  Table prefix: {}", config.migration.table_prefix);
    println!("  Migrations:   {}", config.migration.migrations_dir);
    if config.migration.orm == Orm::Sqlx {
        println!("  Queries:      {}", config.migration.queries_dir);
    }
    if let Some(ref schema) = config.migration.schema {
        println!("  PG schema:    {}", schema);
    }
    println!();

    println!("Enabled plugins:");
    for plugin in &config.plugins.enabled {
        println!("  + {plugin}");
    }

    // Show disabled plugins
    let disabled: Vec<&&str> = yauth_migration::ALL_PLUGINS
        .iter()
        .filter(|p| !config.plugins.enabled.contains(&p.to_string()))
        .collect();
    if !disabled.is_empty() {
        println!();
        println!("Available plugins (not enabled):");
        for plugin in disabled {
            println!("  - {plugin}");
        }
    }

    // Show migration files if they exist
    let migrations_dir = Path::new(&config.migration.migrations_dir);
    if migrations_dir.exists() {
        println!();
        println!("Migration files:");
        let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.contains("yauth")
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            println!("  {}", entry.file_name().to_string_lossy());
        }
    }

    // Show query files if they exist (sqlx only)
    if config.migration.orm == Orm::Sqlx {
        let queries_dir = Path::new(&config.migration.queries_dir);
        if queries_dir.exists() {
            println!();
            let mut entries: Vec<_> = std::fs::read_dir(queries_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sql"))
                .collect();
            entries.sort_by_key(|e| e.file_name());
            println!("Query files ({}):", entries.len());
            for entry in entries {
                println!("  {}", entry.file_name().to_string_lossy());
            }
        }
    }

    Ok(())
}

/// `cargo yauth generate` -- regenerate migration SQL from current config.
pub fn generate(config_path: &Path, check: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = YAuthConfig::load(config_path)?;
    let migration = generate::generate_init(&config)?;

    if check {
        // In --check mode, generated paths contain a fresh timestamp/sequence number
        // that won't match existing files. Instead, find existing files by filename
        // pattern and compare content only.
        let migrations_dir = Path::new(&config.migration.migrations_dir);
        let mut stale = false;

        for (generated_path, expected_content) in &migration.files {
            // Query files live outside migrations_dir -- check them directly
            if is_query_file(generated_path, &config) {
                if generated_path.exists() {
                    let actual = std::fs::read_to_string(generated_path)?;
                    if actual != *expected_content {
                        eprintln!(
                            "STALE: {} does not match generated content",
                            generated_path.display()
                        );
                        eprintln!("{}", format_sql_diff(&actual, expected_content));
                        stale = true;
                    }
                } else {
                    eprintln!("MISSING: expected query file {}", generated_path.display());
                    stale = true;
                }
                continue;
            }

            match find_existing_file(migrations_dir, generated_path, &config) {
                Some(existing_path) => {
                    let actual = std::fs::read_to_string(&existing_path)?;
                    if actual != *expected_content {
                        eprintln!(
                            "STALE: {} does not match generated content",
                            existing_path.display()
                        );
                        eprintln!("{}", format_sql_diff(&actual, expected_content));
                        stale = true;
                    }
                }
                None => {
                    // Show the filename portion for clarity (not the timestamped path)
                    let filename = generated_path
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| generated_path.display().to_string());
                    eprintln!(
                        "MISSING: no existing file matches expected '{filename}' in {}",
                        migrations_dir.display()
                    );
                    stale = true;
                }
            }
        }

        if stale {
            eprintln!("\nGenerated artifacts are stale. Run `cargo yauth generate` to update.");
            std::process::exit(1);
        } else {
            println!("All generated artifacts are up to date.");
        }
    } else {
        write_migration(&migration)?;
        for (path, _) in &migration.files {
            println!("  Generated {}", path.display());
        }
        // Print guided next-step instructions
        print_next_steps(&config, &migration);
    }

    Ok(())
}

/// Check if a generated file path is a query file (lives in queries_dir, not migrations_dir).
fn is_query_file(path: &Path, config: &YAuthConfig) -> bool {
    if config.migration.orm != Orm::Sqlx {
        return false;
    }
    let queries_dir = Path::new(&config.migration.queries_dir);
    path.starts_with(queries_dir)
}

/// Find an existing file on disk that corresponds to a generated file path.
///
/// Generated paths contain timestamps or sequence numbers that won't match
/// existing files. This function searches the migrations directory for files
/// that match the expected pattern, ignoring the timestamp/number prefix.
///
/// Matching strategies by ORM:
/// - **Diesel:** generated path is `<migrations_dir>/<timestamp>_<name>/up.sql` or `down.sql`.
///   We scan for any subdirectory ending in `_<name>` and check for the file inside.
///   For `schema.rs`, it lives directly in `<migrations_dir>/schema.rs`.
/// - **Sqlx:** generated path is `<migrations_dir>/<number>_<name>.sql`.
///   We scan for any file ending in `_<name>.sql`.
fn find_existing_file(
    migrations_dir: &Path,
    generated_path: &Path,
    config: &YAuthConfig,
) -> Option<std::path::PathBuf> {
    // If the file exists at the exact path, use it (handles schema.rs, raw files, etc.)
    if generated_path.exists() {
        return Some(generated_path.to_path_buf());
    }

    if !migrations_dir.exists() {
        return None;
    }

    match config.migration.orm {
        yauth_migration::Orm::Diesel => {
            // Generated: <migrations_dir>/<timestamp>_<name>/<file>
            // Extract the migration name suffix (e.g., "yauth_init") and the filename (e.g., "up.sql")
            let file_name = generated_path.file_name()?;
            let parent = generated_path.parent()?;
            let dir_name = parent.file_name()?.to_string_lossy();
            // Strip the timestamp prefix: "20260406223506_yauth_init" -> "yauth_init"
            let suffix = dir_name
                .find('_')
                .map(|i| &dir_name[i + 1..])
                .unwrap_or(&dir_name);

            // Scan for a directory ending with _<suffix>
            for entry in std::fs::read_dir(migrations_dir).ok()? {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(&format!("_{suffix}")) {
                        let candidate = entry.path().join(file_name);
                        if candidate.exists() {
                            return Some(candidate);
                        }
                    }
                }
            }
            None
        }
        yauth_migration::Orm::Sqlx => {
            // Generated: <migrations_dir>/<number>_<name>.sql
            // Extract the name suffix (e.g., "yauth_init.sql")
            let file_name = generated_path.file_name()?.to_string_lossy();
            // Strip the number prefix: "00000001_yauth_init.sql" -> "yauth_init.sql"
            let suffix = file_name
                .find('_')
                .map(|i| &file_name[i + 1..])
                .unwrap_or(&file_name);

            for entry in std::fs::read_dir(migrations_dir).ok()? {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(&format!("_{suffix}")) {
                        return Some(entry.path());
                    }
                }
            }
            None
        }
        yauth_migration::Orm::SeaOrm => {
            // Generated: <migrations_dir>/m<timestamp>_<name>/<file>  (same as diesel but with m prefix)
            // Also handles entities/ subdirectory files
            let file_name = generated_path.file_name()?;
            let parent = generated_path.parent()?;
            let parent_name = parent.file_name()?.to_string_lossy();

            // Handle entities/ subdirectory
            if parent_name == "entities" {
                let entities_dir = migrations_dir.join("entities");
                let candidate = entities_dir.join(file_name);
                if candidate.exists() {
                    return Some(candidate);
                }
                return None;
            }

            // Handle migration directories: m<timestamp>_<name>/<file>
            let suffix = parent_name
                .find('_')
                .map(|i| &parent_name[i + 1..])
                .unwrap_or(&parent_name);

            for entry in std::fs::read_dir(migrations_dir).ok()? {
                let entry = entry.ok()?;
                if entry.file_type().ok()?.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(&format!("_{suffix}")) {
                        let candidate = entry.path().join(file_name);
                        if candidate.exists() {
                            return Some(candidate);
                        }
                    }
                }
            }
            None
        }
        yauth_migration::Orm::Toasty => {
            // Generated paths: <migrations_dir>/models.rs
            //                  <migrations_dir>/Toasty.toml
            //                  <migrations_dir>/bin/toasty-dev.rs
            // No timestamp prefix to strip — the scaffolding file names are
            // stable — so just replay the exact relative path.
            let rel = generated_path.strip_prefix(migrations_dir).ok()?;
            let candidate = migrations_dir.join(rel);
            if candidate.exists() {
                return Some(candidate);
            }
            None
        }
    }
}

/// Print guided next-step instructions after generating files.
fn print_next_steps(config: &YAuthConfig, migration: &generate::GeneratedMigration) {
    if migration.files.is_empty() && migration.removed_files.is_empty() {
        println!("\n{}", migration.description);
        return;
    }

    // Count migration files vs query files
    let queries_dir_prefix = &config.migration.queries_dir;
    let mut migration_count = 0;
    let mut query_count = 0;

    for (path, _) in &migration.files {
        if path.starts_with(queries_dir_prefix) {
            query_count += 1;
        } else {
            migration_count += 1;
        }
    }

    println!();
    match config.migration.orm {
        Orm::Diesel => {
            if migration_count > 0 {
                println!("Next: run `diesel migration run` to apply");
            }
        }
        Orm::Sqlx => {
            if migration_count > 0 {
                println!("Next: run `sqlx migrate run` to apply");
            }
            if query_count > 0 {
                println!(
                    "Created {} query files in {}/",
                    query_count, config.migration.queries_dir
                );
                println!(
                    "Use with sqlx::query_file!(\"{}/<name>.sql\")",
                    config.migration.queries_dir
                );
            }
        }
        Orm::SeaOrm => {
            if migration_count > 0 {
                println!("Next: run `sea-orm-cli migrate up` to apply");
            }
        }
        Orm::Toasty => {
            if migration_count > 0 {
                println!(
                    "Toasty scaffolding generated. Next steps:\n\
                     - Add `toasty = {{ version = \"0.4\", features = [\"jiff\"] }}` and\n\
                       `jiff = \"0.2\"` to your Cargo.toml.\n\
                     - Register the models and apply migrations at startup:\n\
                       let db = toasty::Db::builder()\n\
                           .table_name_prefix(\"yauth_\")\n\
                           .models(toasty::models!(crate::*))\n\
                           .connect(&database_url).await?;\n\
                       yauth_toasty::apply_migrations(&db).await?;\n\
                     - Generate migrations from future model changes with:\n\
                       cargo run --bin toasty-dev --features dev-cli -- migration generate --name <name>"
                );
            }
        }
    }
}

// -- Interactive prompt helpers --

fn prompt_select(label: &str, options: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let selection = dialoguer::Select::new()
        .with_prompt(label)
        .items(options)
        .default(0)
        .interact()?;
    Ok(options[selection].to_string())
}

fn prompt_multi_select(
    label: &str,
    options: &[&str],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let selections = dialoguer::MultiSelect::new()
        .with_prompt(label)
        .items(options)
        .interact()?;

    Ok(selections
        .into_iter()
        .map(|i| options[i].to_string())
        .collect())
}
