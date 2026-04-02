use std::time::Duration;

use testcontainers::ImageExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use yauth::AsyncDieselConnectionManager;
use yauth::AsyncPgConnection;
use yauth::DieselPool;
use yauth::RunQueryDsl;
use yauth::state::DbPool;

/// Holds a database pool and optionally the testcontainer that backs it.
pub struct TestDb {
    pub pool: DbPool,
    _container: Option<testcontainers::ContainerAsync<Postgres>>,
}

impl TestDb {
    pub async fn try_new() -> Option<Self> {
        if let Ok(url) = std::env::var("DATABASE_URL") {
            let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
            let pool = DieselPool::builder(manager)
                .max_size(4)
                .build()
                .expect("failed to build diesel deadpool");

            match pool.get().await {
                Ok(_) => {
                    return Some(Self {
                        pool,
                        _container: None,
                    });
                }
                Err(e) => {
                    eprintln!("DATABASE_URL set but cannot connect: {e}");
                }
            }
        }

        let container = match Postgres::default().with_tag("17-alpine").start().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot start testcontainer (Docker unavailable?): {e}");
                return None;
            }
        };

        let host_port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("failed to get postgres port");

        let url = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(&url);
        let pool = DieselPool::builder(manager)
            .max_size(4)
            .build()
            .expect("failed to build diesel deadpool");

        for attempt in 1..=30 {
            match pool.get().await {
                Ok(_) => {
                    return Some(Self {
                        pool,
                        _container: Some(container),
                    });
                }
                Err(_) if attempt < 30 => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    eprintln!("Testcontainer started but postgres not ready after 15s: {e}");
                    return None;
                }
            }
        }
        None
    }
}

pub async fn drop_yauth_tables(pool: &DbPool) {
    let mut conn = pool.get().await.expect("pool connection");
    diesel::sql_query(
        "DO $$ DECLARE r RECORD; BEGIN \
         FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'yauth_%') LOOP \
         EXECUTE 'DROP TABLE IF EXISTS public.' || quote_ident(r.tablename) || ' CASCADE'; \
         END LOOP; END $$;",
    )
    .execute(&mut conn)
    .await
    .expect("failed to drop yauth tables");
}
