use async_trait::async_trait;
use hangar_domain::health::{ComponentHealth, DatabaseHealth, HealthCheckPort};
use sqlx::PgPool;
use std::time::Instant;

pub struct PostgresHealthCheck {
    pool: PgPool,
    max_connections: u32,
}

impl PostgresHealthCheck {
    pub fn new(pool: PgPool, max_connections: u32) -> Self {
        Self { pool, max_connections }
    }
}

#[async_trait]
impl HealthCheckPort for PostgresHealthCheck {
    async fn check(&self) -> DatabaseHealth {
        let start = Instant::now();
        let version: Result<(String,), _> = sqlx::query_as("SELECT current_setting('server_version')").fetch_one(&self.pool).await;
        let response_time_ms = start.elapsed().as_millis() as u64;

        let (status, server_version) = match version {
            Ok((version,)) => (ComponentHealth::Up, Some(version)),
            Err(e) => (ComponentHealth::Down(e.to_string()), None),
        };

        DatabaseHealth {
            status,
            response_time_ms,
            active_connections: self.pool.size(),
            max_connections: self.max_connections,
            server_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn reports_up_with_connection_and_version_details_when_postgres_is_reachable(pool: sqlx::PgPool) {
        let health = PostgresHealthCheck::new(pool, 10);
        let status = health.check().await;

        assert_eq!(status.status, ComponentHealth::Up);
        assert_eq!(status.max_connections, 10);
        assert!(status.server_version.is_some());
    }
}
