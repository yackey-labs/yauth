//! Dev-only CLI for generating Toasty migrations from model changes.
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
