use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::metrics_snapshot::{MetricsSnapshot, MetricsSnapshotRepositoryPort};
use sqlx::PgPool;

pub struct PostgresMetricsSnapshotRepository {
    pool: PgPool,
}

impl PostgresMetricsSnapshotRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MetricsSnapshotRepositoryPort for PostgresMetricsSnapshotRepository {
    async fn save(&self, snapshot: &MetricsSnapshot) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO metrics_snapshots (id, recorded_at, total_users, total_repositories, total_storage_bytes) \
             VALUES ($1, $2, $3, $4, $5)",
            snapshot.id,
            snapshot.recorded_at,
            snapshot.total_users,
            snapshot.total_repositories,
            snapshot.total_storage_bytes,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn list_since(&self, since: DateTime<Utc>) -> Result<Vec<MetricsSnapshot>, DomainError> {
        let rows = sqlx::query_as!(
            MetricsSnapshot,
            "SELECT id, recorded_at, total_users, total_repositories, total_storage_bytes \
             FROM metrics_snapshots WHERE recorded_at >= $1 ORDER BY recorded_at ASC",
            since,
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use uuid::Uuid;

    fn sample(recorded_at: DateTime<Utc>, total_users: i64) -> MetricsSnapshot {
        MetricsSnapshot { id: Uuid::new_v4(), recorded_at, total_users, total_repositories: 2, total_storage_bytes: 12345 }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn returns_no_snapshots_when_none_have_been_recorded(pool: PgPool) {
        let repo = PostgresMetricsSnapshotRepository::new(pool);
        assert!(repo.list_since(Utc::now() - Duration::days(30)).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lists_snapshots_oldest_first(pool: PgPool) {
        let repo = PostgresMetricsSnapshotRepository::new(pool);
        let now = Utc::now();
        let older = sample(now - Duration::hours(2), 1);
        let newer = sample(now - Duration::hours(1), 2);
        repo.save(&newer).await.unwrap();
        repo.save(&older).await.unwrap();

        let snapshots = repo.list_since(now - Duration::days(1)).await.unwrap();

        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].id, older.id);
        assert_eq!(snapshots[1].id, newer.id);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn excludes_snapshots_recorded_before_the_since_cutoff(pool: PgPool) {
        let repo = PostgresMetricsSnapshotRepository::new(pool);
        let now = Utc::now();
        let too_old = sample(now - Duration::days(40), 1);
        let recent = sample(now - Duration::days(1), 2);
        repo.save(&too_old).await.unwrap();
        repo.save(&recent).await.unwrap();

        let snapshots = repo.list_since(now - Duration::days(30)).await.unwrap();

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].id, recent.id);
    }
}
