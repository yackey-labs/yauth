# Migrating from SeaORM to diesel-async

> **Note:** As of yauth v0.2.0, diesel-async is the only supported database backend. SeaORM has been fully removed. This guide is preserved for users migrating their own app code from SeaORM to diesel-async.

## Prerequisites

- **PostgreSQL 14+**
- **diesel CLI** (for generating app-side migrations and schema):
  ```bash
  cargo install diesel_cli --no-default-features --features postgres
  ```

## Step 1: Update Cargo.toml

Starting with yauth v0.2.0, diesel-async is the default — no feature flags needed for the backend:

```toml
[dependencies]
yauth = { version = "0.2", features = ["email-password", "passkey", "mfa"] }

# Direct deps for your own app queries
diesel = { version = "2", features = ["postgres", "uuid", "chrono", "serde_json"] }
diesel-async = { version = "0.8", features = ["postgres", "deadpool"] }
```

The `full` convenience feature enables all yauth plugins and all backends:

```toml
yauth = { version = "0.2", features = ["full"] }
```

## Step 2: Update DB Pool Initialization

Replace SeaORM's `Database::connect()` with a `DieselBackend`:

```diff
-use sea_orm::Database;
-
-let db = Database::connect(&database_url).await?;
+use yauth::backends::diesel_pg::DieselBackend;
+
+let backend = DieselBackend::new(&database_url)?;
+// Or with a custom PostgreSQL schema:
+// let backend = DieselBackend::with_schema(&database_url, "auth")?;
```

If you need direct pool access for your own queries, use `DieselBackend::from_pool()` with an existing pool.

## Step 3: Update AppState

yauth re-exports the pool type as `yauth::DieselPool` and the connection type as `yauth::AsyncPgConnection` for convenience. The internal `DbPool` type alias resolves to the diesel pool.

If your AppState previously held a `sea_orm::DatabaseConnection`, replace it:

```diff
-use sea_orm::DatabaseConnection;
+use yauth::backends::diesel_pg::DieselPool;

 pub struct AppState {
-    pub db: DatabaseConnection,
+    pub db: DieselPool,
     pub yauth: YAuthState,
 }
```

The `YAuthBuilder` now accepts a `DatabaseBackend` implementation instead of a raw pool. `build()` is async and returns `Result`:

```rust
let backend = DieselBackend::new(&database_url)?;
let yauth = YAuthBuilder::new(backend, yauth_config)
    .with_email_password(ep_config)
    .build()
    .await?;
```

## Step 4: Update Migrations

### yauth tables

yauth migrations are explicit — call `backend.migrate(&EnabledFeatures::from_compile_flags()).await?` before `build()`. Only tables for your enabled features are created, and the operation is idempotent.

### App tables

Write your own migrations as SQL files in diesel's standard format:

```
migrations/
  2024-01-15-120000_create_items/
    up.sql
    down.sql
```

Run them with diesel's embedded migrations macro:

```rust
use diesel_async_migrations::{embed_migrations, EmbeddedMigrations};
use diesel_async::AsyncConnection;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

// Run at startup after yauth migrations
let mut conn = pool.get().await?;
conn.run_pending_migrations(MIGRATIONS).await?;
```

Or run them via the CLI during development:

```bash
diesel migration run --database-url "$DATABASE_URL"
```

## Step 5: Update Entity Definitions

Replace SeaORM entity models with diesel table macros and derive structs.

**Before (SeaORM):**

```rust
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, DeriveEntityModel)]
#[sea_orm(table_name = "items")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub user_id: Uuid,
    pub created_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
```

**After (diesel):**

```rust
use diesel::prelude::*;
use uuid::Uuid;
use chrono::{DateTime, FixedOffset};

diesel::table! {
    items (id) {
        id -> Uuid,
        name -> Text,
        description -> Nullable<Text>,
        user_id -> Uuid,
        created_at -> Timestamptz,
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = items)]
pub struct Item {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub user_id: Uuid,
    pub created_at: DateTime<FixedOffset>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = items)]
pub struct NewItem<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub user_id: Uuid,
}
```

You can also generate the `table!` macro automatically from your database:

```bash
diesel print-schema --database-url "$DATABASE_URL" > src/schema.rs
```

## Step 6: Update Query Handlers

All queries need a connection from the pool. Get one at the start of each handler:

```rust
let mut conn = pool.get().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
```

### SELECT

```diff
-// SeaORM
-let items = items::Entity::find()
-    .filter(items::Column::UserId.eq(user_id))
-    .all(&db)
-    .await?;
+// Diesel
+use diesel::prelude::*;
+use diesel_async::RunQueryDsl;
+
+let results = items::table
+    .filter(items::user_id.eq(user_id))
+    .select(Item::as_select())
+    .load::<Item>(&mut conn)
+    .await?;
```

### SELECT one

```diff
-let item = items::Entity::find_by_id(id)
-    .one(&db)
-    .await?
-    .ok_or(ApiError::NotFound)?;
+let item = items::table
+    .find(id)
+    .select(Item::as_select())
+    .first::<Item>(&mut conn)
+    .await
+    .optional()?
+    .ok_or(ApiError::NotFound)?;
```

### INSERT

```diff
-let model = items::ActiveModel {
-    id: Set(Uuid::new_v4()),
-    name: Set(name),
-    user_id: Set(user_id),
-    ..Default::default()
-};
-let result = model.insert(&db).await?;
+let new_item = NewItem {
+    id: Uuid::new_v4(),
+    name: &name,
+    description: None,
+    user_id,
+};
+let result = diesel::insert_into(items::table)
+    .values(&new_item)
+    .returning(Item::as_returning())
+    .get_result::<Item>(&mut conn)
+    .await?;
```

### UPDATE

```diff
-let mut model: items::ActiveModel = item.into();
-model.name = Set(new_name);
-model.update(&db).await?;
+diesel::update(items::table.find(id))
+    .set(items::name.eq(new_name))
+    .execute(&mut conn)
+    .await?;
```

### DELETE

```diff
-items::Entity::delete_by_id(id).exec(&db).await?;
+diesel::delete(items::table.find(id))
+    .execute(&mut conn)
+    .await?;
```

## Step 7: Pool Sharing

If you need to share a pool between yauth and your own app queries, use `DieselBackend::from_pool()`:

```rust
use diesel_async::pooled_connection::{deadpool::Pool, AsyncDieselConnectionManager};
use diesel_async::AsyncPgConnection;
use yauth::prelude::*;
use yauth::backends::diesel_pg::DieselBackend;

// Create pool
let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&database_url);
let pool = Pool::builder(config)
    .max_size(16)  // tune for your workload
    .build()?;

// Build yauth with the shared pool
let backend = DieselBackend::from_pool(pool.clone());
backend.migrate(&EnabledFeatures::from_compile_flags()).await?;
let yauth = YAuthBuilder::new(backend, yauth_config)
    .with_email_password(ep_config)
    .build()
    .await?;

// Use the same pool for app queries
let mut conn = pool.get().await?;
let items = items::table.load::<Item>(&mut conn).await?;
```

## Data Migration

No data migration is needed. Both SeaORM and diesel-async talk to the same PostgreSQL tables with the same column names, types, and constraints. Switching the ORM backend does not change the schema. The `yauth_` tables created by SeaORM migrations are identical to those created by diesel migrations.

If you already have data in your database, just switch to yauth v0.2.0 and redeploy. The diesel migrations use `CREATE TABLE IF NOT EXISTS`, so they will not conflict with existing tables.

## Troubleshooting

### `deadpool::PoolError::Timeout` -- pool exhausted

The connection pool ran out of available connections. Either increase the pool size or ensure you are not holding connections across `.await` points:

```rust
let pool = Pool::builder(config)
    .max_size(32)  // default is 8-16 depending on deadpool version
    .build()?;
```

### Type mismatches

Diesel maps PostgreSQL types to Rust types differently from SeaORM in some cases:

| PostgreSQL | SeaORM Rust type | Diesel Rust type |
|---|---|---|
| `TIMESTAMPTZ` | `DateTimeWithTimeZone` | `DateTime<FixedOffset>` or `DateTime<Utc>` |
| `JSONB` | `serde_json::Value` | `serde_json::Value` (requires `serde_json` feature) |
| `UUID` | `uuid::Uuid` | `uuid::Uuid` (requires `uuid` feature) |
| `TEXT[]` | `Vec<String>` | Not built-in; use `diesel::sql_types::Array<Text>` |

Ensure your `diesel` dependency has the correct feature flags:

```toml
diesel = { version = "2", features = ["postgres", "uuid", "chrono", "serde_json"] }
```

### `diesel::result::Error::NotFound` vs `Option`

Diesel's `.first()` returns `Err(NotFound)` when no row matches, unlike SeaORM which returns `Ok(None)`. Use `.optional()` from `diesel::result::OptionalExtension` to get `Option` behavior:

```rust
use diesel::result::OptionalExtension;

let item = items::table
    .find(id)
    .first::<Item>(&mut conn)
    .await
    .optional()?;  // Ok(None) instead of Err(NotFound)
```
