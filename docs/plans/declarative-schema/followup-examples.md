# Follow-up: Update examples + add diesel-libsql example

After M1 lands, update all examples to use the new migration API and add a diesel-libsql example.

## What must work:

1. `examples/server.rs` — remove any manual migration calls (migrations now run inside `build()` via `DatabaseBackend::migrate()`). Verify the Diesel and memory backends both work as before.
2. `examples/e2e_test.rs` — schema reset should use `DieselPgBackend` migration API, not raw SQL `DROP SCHEMA CASCADE`. Fresh schema setup uses the declarative system.
3. `examples/libsql/` — new example showing yauth with diesel-libsql:
   - `YAUTH_BACKEND=libsql DATABASE_URL=file:yauth.db` for local SQLite file
   - `YAUTH_BACKEND=libsql DATABASE_URL=libsql://your-db.turso.io LIBSQL_AUTH_TOKEN=...` for Turso remote
   - Same auth flow as the main server example (register, login, session, logout)
   - No Docker, no Postgres — just a local file or Turso URL
4. Example server's `YAUTH_BACKEND` env var supports `diesel`, `memory`, and `libsql`
5. README updated with all three backend options

## After building, prove it works:

- `cargo run --example server --features full` with `YAUTH_BACKEND=diesel` + Postgres — works as before
- `YAUTH_BACKEND=memory cargo run --example server --features full` — works without any database
- `YAUTH_BACKEND=libsql DATABASE_URL=file:/tmp/test.db cargo run --example server --features full` — creates SQLite file, full auth flows work
- `cargo run --example e2e_test --features full` — e2e tests pass with new migration API
- Delete the SQLite file, restart with same URL — migrations recreate all tables
