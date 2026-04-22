//! Minimal yauth app using the Toasty ORM backend over SQLite.
//!
//! Run with:
//!
//! ```bash
//! cargo run --manifest-path crates/yauth-toasty/Cargo.toml \
//!     --example toasty_backend \
//!     --features email-password,sqlite
//! ```
//!
//! Then try it out:
//!
//! ```bash
//! curl -s -X POST http://localhost:3000/register \
//!   -H 'Content-Type: application/json' \
//!   -d '{"email":"test@example.com","password":"SecureP@ss123!"}'
//! ```
//!
//! The example uses a file-backed SQLite database (`./example.db`) because
//! Toasty's SQLite driver opens a fresh connection per query — an in-memory
//! database would produce a fresh schema for every request. `example.db` is
//! gitignored so you can safely delete it between runs.

use yauth::YAuthBuilder;
use yauth::config::{EmailPasswordConfig, YAuthConfig};
use yauth_toasty::{ToastySqliteBackend, apply_migrations};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // 1. Build a Toasty Db with every yauth model registered.
    let db = toasty::Db::builder()
        .table_name_prefix("yauth_")
        .models(yauth_toasty::all_models!())
        .connect("sqlite:./example.db")
        .await?;

    // 2. Apply embedded migrations (idempotent — safe on every startup).
    apply_migrations(&db).await?;

    // 3. Wrap the Db as a yauth backend.
    let backend = ToastySqliteBackend::from_db(db);
    let yauth = YAuthBuilder::new(backend, YAuthConfig::default())
        .with_email_password(EmailPasswordConfig::default())
        .build()
        .await?;

    // 4. Mount on Axum and serve.
    let app = axum::Router::new()
        .merge(yauth.router())
        .with_state(yauth.state().clone());

    let addr = "0.0.0.0:3000";
    println!("yauth-toasty example listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
