use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentHealth {
    Up,
    Down(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DatabaseHealth {
    pub status: ComponentHealth,
    pub response_time_ms: u64,
    pub active_connections: u32,
    pub max_connections: u32,
    /// `None` when `status` is `Down` — the version query never ran.
    pub server_version: Option<String>,
}

#[async_trait]
pub trait HealthCheckPort: Send + Sync {
    async fn check(&self) -> DatabaseHealth;
}
