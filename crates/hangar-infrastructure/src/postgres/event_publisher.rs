use async_trait::async_trait;
use hangar_domain::audit::{AuditEntry, AuditQueryFilter, DockerRegistryEvent, EventPublisherPort, NpmPackageEvent, SecurityEvent};
use hangar_domain::error::EventStoreError;
use crate::error_ext::StorageErr;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresEventPublisher {
    pool: PgPool,
}

impl PostgresEventPublisher {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EventPublisherPort for PostgresEventPublisher {
    async fn publish_security_event(&self, event: SecurityEvent, actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        let payload = serde_json::to_value(&event).storage_err()?;
        sqlx::query!(
            "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version, actor_id) \
             VALUES ('Security', $1, $2, $3, 1, $4)",
            Uuid::new_v4().to_string(),
            event.event_type(),
            payload,
            actor_id
        )
        .execute(&self.pool)
        .await
        .storage_err()?;
        Ok(())
    }

    async fn query_audit_log(&self, filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, EventStoreError> {
        let rows = sqlx::query!(
            r#"
            SELECT aggregate_type, aggregate_id, event_type, payload, occurred_at, actor_id
            FROM domain_events
            WHERE ($1::text IS NULL OR aggregate_type = $1)
              AND ($2::text IS NULL OR aggregate_id = $2)
              AND ($3::uuid IS NULL OR actor_id = $3)
              AND ($4::timestamptz IS NULL OR occurred_at >= $4)
              AND ($5::timestamptz IS NULL OR occurred_at <= $5)
              AND ($6::text IS NULL OR aggregate_type != $6)
            ORDER BY occurred_at DESC
            LIMIT 200
            "#,
            filter.aggregate_type,
            filter.aggregate_id,
            filter.actor_id,
            filter.from,
            filter.to,
            filter.exclude_aggregate_type
        )
        .fetch_all(&self.pool)
        .await
        .storage_err()?;

        Ok(rows
            .into_iter()
            .map(|row| AuditEntry {
                aggregate_type: row.aggregate_type,
                aggregate_id: row.aggregate_id,
                event_type: row.event_type,
                payload: row.payload,
                occurred_at: row.occurred_at,
                actor_id: row.actor_id,
            })
            .collect())
    }

    async fn publish_npm_event(&self, event: NpmPackageEvent, npm_package_id: Uuid, actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        let payload = serde_json::to_value(&event).storage_err()?;

        // `version` must increment per aggregate — advisory-lock-then-append,
        // same pattern as PermissionStore/PackageRepositoryStore.
        let mut tx = self.pool.begin().await.storage_err()?;

        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1))", npm_package_id.to_string())
            .execute(&mut *tx)
            .await
            .storage_err()?;

        let current_version: i64 = sqlx::query_scalar!(
            "SELECT version FROM domain_events \
             WHERE aggregate_type = 'NpmPackage' AND aggregate_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE",
            npm_package_id.to_string()
        )
        .fetch_optional(&mut *tx)
        .await
        .storage_err()?
        .unwrap_or(0);
        let next_version = current_version + 1;

        sqlx::query!(
            "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version, actor_id) \
             VALUES ('NpmPackage', $1, $2, $3, $4, $5)",
            npm_package_id.to_string(),
            event.event_type(),
            payload,
            next_version,
            actor_id
        )
        .execute(&mut *tx)
        .await
        .storage_err()?;

        tx.commit().await.storage_err()?;
        Ok(())
    }

    async fn publish_docker_event(&self, event: DockerRegistryEvent, package_repository_id: Uuid, actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        let payload = serde_json::to_value(&event).storage_err()?;

        // Same advisory-lock-then-append pattern as `publish_npm_event`.
        let mut tx = self.pool.begin().await.storage_err()?;

        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1))", package_repository_id.to_string())
            .execute(&mut *tx)
            .await
            .storage_err()?;

        let current_version: i64 = sqlx::query_scalar!(
            "SELECT version FROM domain_events \
             WHERE aggregate_type = 'DockerRegistry' AND aggregate_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE",
            package_repository_id.to_string()
        )
        .fetch_optional(&mut *tx)
        .await
        .storage_err()?
        .unwrap_or(0);
        let next_version = current_version + 1;

        sqlx::query!(
            "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version, actor_id) \
             VALUES ('DockerRegistry', $1, $2, $3, $4, $5)",
            package_repository_id.to_string(),
            event.event_type(),
            payload,
            next_version,
            actor_id
        )
        .execute(&mut *tx)
        .await
        .storage_err()?;

        tx.commit().await.storage_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn publishing_two_npm_events_for_the_same_package_does_not_collide_on_version(pool: sqlx::PgPool) {
        let publisher = PostgresEventPublisher::new(pool);
        let package_id = Uuid::new_v4();

        publisher
            .publish_npm_event(
                NpmPackageEvent::PackagePushed { package_name: "left-pad".to_string(), version: "1.0.0".to_string() },
                package_id,
                None,
            )
            .await
            .unwrap();
        publisher
            .publish_npm_event(
                NpmPackageEvent::DistTagChanged { package_name: "left-pad".to_string(), tag: "beta".to_string(), version: "1.0.0".to_string() },
                package_id,
                None,
            )
            .await
            .unwrap();

        let entries = publisher
            .query_audit_log(AuditQueryFilter { aggregate_type: Some("NpmPackage".to_string()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.aggregate_id == package_id.to_string()));
    }

    #[sqlx::test]
    async fn publishes_and_queries_a_security_event(pool: sqlx::PgPool) {
        let publisher = PostgresEventPublisher::new(pool);
        publisher
            .publish_security_event(SecurityEvent::LoginFailed { username: "florian".to_string(), ip: "127.0.0.1".to_string() }, None)
            .await
            .unwrap();

        let entries = publisher
            .query_audit_log(AuditQueryFilter { aggregate_type: Some("Security".to_string()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "LoginFailed");
    }

    #[sqlx::test]
    async fn filters_by_actor_id(pool: sqlx::PgPool) {
        let publisher = PostgresEventPublisher::new(pool);
        let actor_id = Uuid::new_v4();
        publisher
            .publish_security_event(
                SecurityEvent::AccessDenied { user_id: actor_id, repository_id: Uuid::new_v4(), action: "push".to_string() },
                Some(actor_id),
            )
            .await
            .unwrap();
        publisher
            .publish_security_event(SecurityEvent::LoginFailed { username: "other".to_string(), ip: "10.0.0.1".to_string() }, None)
            .await
            .unwrap();

        let entries = publisher.query_audit_log(AuditQueryFilter { actor_id: Some(actor_id), ..Default::default() }).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event_type, "AccessDenied");
    }

    #[sqlx::test]
    async fn excluding_an_aggregate_type_leaves_the_row_budget_to_the_business_events(pool: sqlx::PgPool) {
        for index in 0..25 {
            sqlx::query(
                "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version) \
                 VALUES ('Security', $1, 'LoginFailed', '{}'::jsonb, 1)",
            )
            .bind(format!("security-{index}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version) \
             VALUES ('Permission', 'perm-1', 'PermissionGranted', '{}'::jsonb, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version) \
             VALUES ('PackageRepository', 'repo-1', 'PackageRepositoryCreated', '{}'::jsonb, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let publisher = PostgresEventPublisher::new(pool);

        let all = publisher.query_audit_log(AuditQueryFilter::default()).await.unwrap();
        assert_eq!(all.len(), 27);

        let entries = publisher
            .query_audit_log(AuditQueryFilter { exclude_aggregate_type: Some("Security".to_string()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.aggregate_type != "Security"));
        let mut event_types: Vec<_> = entries.iter().map(|entry| entry.event_type.as_str()).collect();
        event_types.sort_unstable();
        assert_eq!(event_types, vec!["PackageRepositoryCreated", "PermissionGranted"]);
    }
}
