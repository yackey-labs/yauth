use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;

/// cargo-yauth: Migration management CLI for yauth
///
/// Generates migration files for diesel, sqlx, or raw SQL from a declarative
/// yauth schema definition. Supports interactive and non-interactive modes.
#[derive(Parser)]
#[command(name = "cargo-yauth", bin_name = "cargo")]
struct Cli {
    #[command(subcommand)]
    command: CargoCommand,
}

#[derive(Subcommand)]
enum CargoCommand {
    /// yauth migration management
    Yauth(YauthArgs),
}

#[derive(Parser)]
struct YauthArgs {
    /// Path to yauth.toml config file
    #[arg(short = 'f', long = "config", default_value = "yauth.toml")]
    config_path: PathBuf,

    #[command(subcommand)]
    command: YauthCommand,
}

#[derive(Subcommand)]
enum YauthCommand {
    /// Initialize yauth in a project — creates yauth.toml and initial migration files
    Init {
        /// ORM to generate migration files for (diesel, sqlx, raw)
        #[arg(long)]
        orm: Option<String>,

        /// SQL dialect (postgres, mysql, sqlite)
        #[arg(long)]
        dialect: Option<String>,

        /// Comma-separated list of plugins to enable
        #[arg(long)]
        plugins: Option<String>,

        /// Table name prefix (default: yauth_)
        #[arg(long)]
        prefix: Option<String>,

        /// PostgreSQL schema name
        #[arg(long)]
        schema: Option<String>,

        /// Migrations directory
        #[arg(long)]
        migrations_dir: Option<String>,
    },

    /// Add a plugin and generate its migration
    AddPlugin {
        /// Plugin name (e.g., mfa, passkey, bearer)
        name: String,
    },

    /// Remove a plugin and generate its removal migration
    RemovePlugin {
        /// Plugin name (e.g., mfa, passkey, bearer)
        name: String,
    },

    /// Show current yauth status — enabled plugins and migrations
    Status,

    /// Regenerate migration SQL files from current config
    Generate {
        /// Verify generated artifacts are fresh (exit 1 if stale)
        #[arg(long)]
        check: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let CargoCommand::Yauth(args) = cli.command;

    let result = match args.command {
        YauthCommand::Init {
            orm,
            dialect,
            plugins,
            prefix,
            schema,
            migrations_dir,
        } => commands::init(
            &args.config_path,
            orm,
            dialect,
            plugins,
            prefix,
            schema,
            migrations_dir,
        ),
        YauthCommand::AddPlugin { name } => commands::add_plugin(&args.config_path, &name),
        YauthCommand::RemovePlugin { name } => commands::remove_plugin(&args.config_path, &name),
        YauthCommand::Status => commands::status(&args.config_path),
        YauthCommand::Generate { check } => commands::generate(&args.config_path, check),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
