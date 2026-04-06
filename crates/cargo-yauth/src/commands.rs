//! CLI command implementations.

use std::path::Path;

use yauth_migration::config::YAuthConfig;
use yauth_migration::diff::{format_sql_diff, render_changes_sql, schema_diff};
use yauth_migration::generate::{self, write_migration};
use yauth_migration::{Dialect, collect_schema_for_plugins};

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
        None => prompt_select("ORM", &["diesel", "sqlx", "raw"])?,
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

    println!("\n{}", migration.description);
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
    println!("\n{}", migration.description);
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

    // Update config
    config.save(config_path)?;
    println!("Updated {}", config_path.display());
    println!("\n{}", migration.description);
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

    Ok(())
}

/// `cargo yauth generate` -- regenerate migration SQL from current config.
pub fn generate(config_path: &Path, check: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = YAuthConfig::load(config_path)?;
    let migration = generate::generate_init(&config)?;

    if check {
        // Verify that existing files match what would be generated
        let mut stale = false;
        for (path, expected_content) in &migration.files {
            if path.exists() {
                let actual = std::fs::read_to_string(path)?;
                if actual != *expected_content {
                    eprintln!("STALE: {} does not match generated content", path.display());
                    eprintln!("{}", format_sql_diff(&actual, expected_content));
                    stale = true;
                }
            } else {
                eprintln!("MISSING: {}", path.display());
                stale = true;
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
        println!("\n{}", migration.description);
    }

    Ok(())
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
