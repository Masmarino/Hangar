use async_trait::async_trait;
use hangar_domain::error::EventStoreError;
use crate::error_ext::StorageErr;
use hangar_domain::permission::{PermissionEvent, PermissionEventStorePort, PermissionQueryPort, Role};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresPermissionStore {
    pool: PgPool,
}

impl PostgresPermissionStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn role_to_str(role: Role) -> &'static str {
    match role {
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
    }
}

fn role_from_str(raw: &str) -> Option<Role> {
    match raw {
        "read" => Some(Role::Read),
        "write" => Some(Role::Write),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}

fn aggregate_id(user_id: Uuid, repository_id: Uuid) -> String {
    format!("{user_id}:{repository_id}")
}

#[async_trait]
impl PermissionEventStorePort for PostgresPermissionStore {
    async fn load(&self, user_id: Uuid, repository_id: Uuid) -> Result<(u64, Vec<PermissionEvent>), EventStoreError> {
        let rows = sqlx::query!(
            "SELECT payload, version FROM domain_events \
             WHERE aggregate_type = 'Permission' AND aggregate_id = $1 ORDER BY version",
            aggregate_id(user_id, repository_id)
        )
        .fetch_all(&self.pool)
        .await
        .storage_err()?;

        let mut version = 0u64;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(serde_json::from_value(row.payload).storage_err()?);
            version = row.version as u64;
        }
        Ok((version, events))
    }

    async fn append(
        &self,
        user_id: Uuid,
        repository_id: Uuid,
        expected_version: u64,
        events: Vec<PermissionEvent>,
        actor_id: Uuid,
    ) -> Result<(), EventStoreError> {
        let mut tx = self.pool.begin().await.storage_err()?;

        // Advisory lock first: `FOR UPDATE` below takes no lock on a
        // brand-new aggregate (zero rows), so two first-appends could race.
        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1))", aggregate_id(user_id, repository_id))
            .execute(&mut *tx)
            .await
            .storage_err()?;

        let current_version: i64 = sqlx::query_scalar!(
            "SELECT version FROM domain_events \
             WHERE aggregate_type = 'Permission' AND aggregate_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE",
            aggregate_id(user_id, repository_id)
        )
        .fetch_optional(&mut *tx)
        .await
        .storage_err()?
        .unwrap_or(0);

        if current_version as u64 != expected_version {
            return Err(EventStoreError::ConcurrencyConflict { expected: expected_version, actual: current_version as u64 });
        }

        let mut next_version = current_version;
        let mut latest_role: Option<Role> = None;
        for event in &events {
            next_version += 1;
            let payload = serde_json::to_value(event).storage_err()?;
            sqlx::query!(
                "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version, actor_id) \
                 VALUES ('Permission', $1, $2, $3, $4, $5)",
                aggregate_id(user_id, repository_id),
                event.event_type(),
                payload,
                next_version,
                actor_id
            )
            .execute(&mut *tx)
            .await
            .storage_err()?;

            latest_role = match event {
                PermissionEvent::Granted { role, .. } => Some(*role),
                PermissionEvent::Revoked { .. } => None,
            };
        }

        match latest_role {
            Some(role) => {
                sqlx::query!(
                    "INSERT INTO permission_projections (user_id, repository_id, role, version, updated_at) \
                     VALUES ($1, $2, $3, $4, now()) \
                     ON CONFLICT (user_id, repository_id) \
                     DO UPDATE SET role = EXCLUDED.role, version = EXCLUDED.version, updated_at = now()",
                    user_id,
                    repository_id,
                    role_to_str(role),
                    next_version
                )
                .execute(&mut *tx)
                .await
                .storage_err()?;
            }
            None => {
                sqlx::query!(
                    "DELETE FROM permission_projections WHERE user_id = $1 AND repository_id = $2",
                    user_id,
                    repository_id
                )
                .execute(&mut *tx)
                .await
                .storage_err()?;
            }
        }

        tx.commit().await.storage_err()?;
        Ok(())
    }
}

#[async_trait]
impl PermissionQueryPort for PostgresPermissionStore {
    async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError> {
        let row = sqlx::query!(
            "SELECT role FROM permission_projections WHERE user_id = $1 AND repository_id = $2",
            user_id,
            repository_id
        )
        .fetch_optional(&self.pool)
        .await
        .storage_err()?;
        Ok(row.and_then(|r| role_from_str(&r.role)))
    }

    async fn list_for_repository(&self, repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
        let rows = sqlx::query!("SELECT user_id, role FROM permission_projections WHERE repository_id = $1", repository_id)
            .fetch_all(&self.pool)
            .await
            .storage_err()?;
        Ok(rows.into_iter().filter_map(|r| role_from_str(&r.role).map(|role| (r.user_id, role))).collect())
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
        let rows = sqlx::query!("SELECT repository_id, role FROM permission_projections WHERE user_id = $1", user_id)
            .fetch_all(&self.pool)
            .await
            .storage_err()?;
        Ok(rows.into_iter().filter_map(|r| role_from_str(&r.role).map(|role| (r.repository_id, role))).collect())
    }

    async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError> {
        let rows = sqlx::query!("SELECT user_id, repository_id, role FROM permission_projections")
            .fetch_all(&self.pool)
            .await
            .storage_err()?;
        Ok(rows.into_iter().filter_map(|r| role_from_str(&r.role).map(|role| (r.user_id, r.repository_id, role))).collect())
    }

    async fn count_all(&self) -> Result<usize, EventStoreError> {
        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM permission_projections")
            .fetch_one(&self.pool)
            .await
            .storage_err()?
            .unwrap_or(0);
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn grants_and_reads_back_the_role(pool: sqlx::PgPool) {
        let store = PostgresPermissionStore::new(pool);
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        store
            .append(user_id, repository_id, 0, vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Write }], Uuid::new_v4())
            .await
            .unwrap();

        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), Some(Role::Write));
        let (version, events) = store.load(user_id, repository_id).await.unwrap();
        assert_eq!(version, 1);
        assert_eq!(events.len(), 1);
    }

    #[sqlx::test]
    async fn rejects_a_stale_expected_version(pool: sqlx::PgPool) {
        let store = PostgresPermissionStore::new(pool);
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        store
            .append(user_id, repository_id, 0, vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Read }], Uuid::new_v4())
            .await
            .unwrap();

        let err = store
            .append(user_id, repository_id, 0, vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Admin }], Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(matches!(err, EventStoreError::ConcurrencyConflict { expected: 0, actual: 1 }));
    }

    #[sqlx::test]
    async fn revoking_removes_the_projection_row(pool: sqlx::PgPool) {
        let store = PostgresPermissionStore::new(pool);
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        store
            .append(user_id, repository_id, 0, vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Read }], Uuid::new_v4())
            .await
            .unwrap();
        store
            .append(user_id, repository_id, 1, vec![PermissionEvent::Revoked { user_id, repository_id }], Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), None);
    }

    #[sqlx::test]
    async fn serializes_concurrent_first_appends_for_a_new_aggregate(pool: sqlx::PgPool) {
        let store_a = PostgresPermissionStore::new(pool.clone());
        let store_b = PostgresPermissionStore::new(pool);
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();

        let (result_a, result_b) = tokio::join!(
            store_a.append(
                user_id,
                repository_id,
                0,
                vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Read }],
                Uuid::new_v4()
            ),
            store_b.append(
                user_id,
                repository_id,
                0,
                vec![PermissionEvent::Granted { user_id, repository_id, role: Role::Write }],
                Uuid::new_v4()
            )
        );

        let outcomes = [result_a, result_b];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        let conflicts = outcomes.iter().filter(|r| matches!(r, Err(EventStoreError::ConcurrencyConflict { expected: 0, actual: 1 }))).count();

        assert_eq!(successes, 1, "expected exactly one append to succeed, got: {outcomes:?}");
        assert_eq!(conflicts, 1, "expected the loser to get a clean ConcurrencyConflict{{expected:0, actual:1}}, got: {outcomes:?}");
    }

    #[sqlx::test]
    async fn lists_a_users_permissions_across_repositories(pool: sqlx::PgPool) {
        let store = PostgresPermissionStore::new(pool);
        let user_id = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let other_user = Uuid::new_v4();

        store.append(user_id, repo_a, 0, vec![PermissionEvent::Granted { user_id, repository_id: repo_a, role: Role::Read }], Uuid::new_v4()).await.unwrap();
        store.append(user_id, repo_b, 0, vec![PermissionEvent::Granted { user_id, repository_id: repo_b, role: Role::Admin }], Uuid::new_v4()).await.unwrap();
        store
            .append(other_user, repo_a, 0, vec![PermissionEvent::Granted { user_id: other_user, repository_id: repo_a, role: Role::Write }], Uuid::new_v4())
            .await
            .unwrap();

        let mut entries = store.list_for_user(user_id).await.unwrap();
        entries.sort_by_key(|(repo_id, _)| *repo_id);
        let mut expected = vec![(repo_a, Role::Read), (repo_b, Role::Admin)];
        expected.sort_by_key(|(repo_id, _)| *repo_id);
        assert_eq!(entries, expected);
    }

    #[sqlx::test]
    async fn lists_every_grant_across_every_repository_in_one_call(pool: sqlx::PgPool) {
        let store = PostgresPermissionStore::new(pool);
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        store.append(user_a, repo_a, 0, vec![PermissionEvent::Granted { user_id: user_a, repository_id: repo_a, role: Role::Read }], Uuid::new_v4()).await.unwrap();
        store.append(user_b, repo_b, 0, vec![PermissionEvent::Granted { user_id: user_b, repository_id: repo_b, role: Role::Write }], Uuid::new_v4()).await.unwrap();

        let mut entries = store.list_all().await.unwrap();
        entries.sort_by_key(|(user_id, ..)| *user_id);
        let mut expected = vec![(user_a, repo_a, Role::Read), (user_b, repo_b, Role::Write)];
        expected.sort_by_key(|(user_id, ..)| *user_id);
        assert_eq!(entries, expected);
    }
}
