pub mod memory;
pub mod postgres;

#[derive(Debug, Clone)]
pub enum StoreBackend {
    Memory,
    Postgres,
}

#[async_trait::async_trait]
pub trait RateLimitStore: Send + Sync {
    async fn check(&self, key: &str, limit: u32, window_secs: u64) -> RateLimitResult;
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after: u64,
}

#[async_trait::async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn set(&self, key: &str, value: serde_json::Value, ttl_secs: u64) -> Result<(), String>;
    async fn get(&self, key: &str) -> Result<Option<serde_json::Value>, String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
}
