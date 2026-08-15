use async_trait::async_trait;
use hangar_domain::error::EventStoreError;
use crate::error_ext::StorageErr;
use hangar_domain::package_repository::{
    PackageRepositoryEvent, PackageRepositoryEventStorePort, PackageRepositoryQueryPort, PackageRepositorySummary,
    RepositoryFormat, RepositoryType,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::secret_box;

pub struct PostgresPackageRepositoryStore {
    pool: PgPool,
    /// Derives the AES-256 key for `secret_box`, used to encrypt `remote_password` at rest.
    secrets_encryption_key: String,
}

impl PostgresPackageRepositoryStore {
    pub fn new(pool: PgPool, secrets_encryption_key: String) -> Self {
        Self { pool, secrets_encryption_key }
    }

    /// Encrypts a `Created` event's `remote_password` before it's ever persisted.
    fn encrypt_secrets(&self, event: PackageRepositoryEvent) -> PackageRepositoryEvent {
        match event {
            PackageRepositoryEvent::Created { repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password } => {
                PackageRepositoryEvent::Created {
                    repository_id,
                    organization_id,
                    name,
                    format,
                    repo_type,
                    remote_url,
                    remote_username,
                    remote_password: remote_password.map(|pw| secret_box::encrypt_packed(&pw, &self.secrets_encryption_key)),
                }
            }
            other => other,
        }
    }

    /// The inverse of `encrypt_secrets`, applied when replaying events out of the journal.
    fn decrypt_secrets(&self, event: PackageRepositoryEvent) -> PackageRepositoryEvent {
        match event {
            PackageRepositoryEvent::Created { repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password } => {
                PackageRepositoryEvent::Created {
                    repository_id,
                    organization_id,
                    name,
                    format,
                    repo_type,
                    remote_url,
                    remote_username,
                    remote_password: remote_password.map(|pw| secret_box::decrypt_packed(&pw, &self.secrets_encryption_key)),
                }
            }
            other => other,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_summary(
        &self,
        id: Uuid,
        organization_id: Uuid,
        name: String,
        format: String,
        repo_type: String,
        remote_url: Option<String>,
        remote_username: Option<String>,
        remote_password: Option<String>,
        quota_bytes: Option<i64>,
        retention_keep_last_n: Option<i32>,
    ) -> Result<PackageRepositorySummary, EventStoreError> {
        let repo_type = repo_type_from_str(&repo_type)
            .ok_or_else(|| EventStoreError::Storage(format!("unknown repo_type {repo_type}")))?;

        // Only a Group repository can have members — skip the query for Hosted/Proxy, the overwhelming majority of lookups.
        let members = if repo_type == RepositoryType::Group {
            sqlx::query_scalar!(
                "SELECT member_repository_id FROM package_repository_group_members WHERE group_repository_id = $1 ORDER BY position",
                id
            )
            .fetch_all(&self.pool)
            .await
            .storage_err()?
        } else {
            Vec::new()
        };

        Ok(PackageRepositorySummary {
            id,
            organization_id,
            name,
            format: format_from_str(&format).ok_or_else(|| EventStoreError::Storage(format!("unknown format {format}")))?,
            repo_type,
            remote_url,
            remote_username,
            remote_password: remote_password.map(|pw| secret_box::decrypt_packed(&pw, &self.secrets_encryption_key)),
            group_members: members,
            quota_bytes,
            retention_keep_last_n,
        })
    }
}

fn format_to_str(format: RepositoryFormat) -> &'static str {
    match format {
        RepositoryFormat::Npm => "npm",
        RepositoryFormat::Docker => "docker",
    }
}

fn format_from_str(raw: &str) -> Option<RepositoryFormat> {
    match raw {
        "npm" => Some(RepositoryFormat::Npm),
        "docker" => Some(RepositoryFormat::Docker),
        _ => None,
    }
}

fn repo_type_to_str(repo_type: RepositoryType) -> &'static str {
    match repo_type {
        RepositoryType::Hosted => "hosted",
        RepositoryType::Proxy => "proxy",
        RepositoryType::Group => "group",
    }
}

fn repo_type_from_str(raw: &str) -> Option<RepositoryType> {
    match raw {
        "hosted" => Some(RepositoryType::Hosted),
        "proxy" => Some(RepositoryType::Proxy),
        "group" => Some(RepositoryType::Group),
        _ => None,
    }
}

#[async_trait]
impl PackageRepositoryEventStorePort for PostgresPackageRepositoryStore {
    async fn load(&self, repository_id: Uuid) -> Result<(u64, Vec<PackageRepositoryEvent>), EventStoreError> {
        let rows = sqlx::query!(
            "SELECT payload, version FROM domain_events \
             WHERE aggregate_type = 'PackageRepository' AND aggregate_id = $1 ORDER BY version",
            repository_id.to_string()
        )
        .fetch_all(&self.pool)
        .await
        .storage_err()?;

        let mut version = 0u64;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let event: PackageRepositoryEvent = serde_json::from_value(row.payload).storage_err()?;
            events.push(self.decrypt_secrets(event));
            version = row.version as u64;
        }
        Ok((version, events))
    }

    async fn append(
        &self,
        repository_id: Uuid,
        expected_version: u64,
        events: Vec<PackageRepositoryEvent>,
        actor_id: Uuid,
    ) -> Result<(), EventStoreError> {
        let mut tx = self.pool.begin().await.storage_err()?;

        // Advisory lock first: `FOR UPDATE` below takes no lock on a brand-new aggregate (zero rows), so two first-appends could race.
        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1))", repository_id.to_string())
            .execute(&mut *tx)
            .await
            .storage_err()?;

        let current_version: i64 = sqlx::query_scalar!(
            "SELECT version FROM domain_events \
             WHERE aggregate_type = 'PackageRepository' AND aggregate_id = $1 ORDER BY version DESC LIMIT 1 FOR UPDATE",
            repository_id.to_string()
        )
        .fetch_optional(&mut *tx)
        .await
        .storage_err()?
        .unwrap_or(0);

        if current_version as u64 != expected_version {
            return Err(EventStoreError::ConcurrencyConflict { expected: expected_version, actual: current_version as u64 });
        }

        let mut next_version = current_version;
        for event in events {
            next_version += 1;
            let event = self.encrypt_secrets(event);
            let payload = serde_json::to_value(&event).storage_err()?;
            sqlx::query!(
                "INSERT INTO domain_events (aggregate_type, aggregate_id, event_type, payload, version, actor_id) \
                 VALUES ('PackageRepository', $1, $2, $3, $4, $5)",
                repository_id.to_string(),
                event.event_type(),
                payload,
                next_version,
                actor_id
            )
            .execute(&mut *tx)
            .await
            .storage_err()?;

            apply_to_projection(&mut tx, repository_id, &event, next_version).await?;
        }

        tx.commit().await.storage_err()?;
        Ok(())
    }
}

async fn apply_to_projection(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repository_id: Uuid,
    event: &PackageRepositoryEvent,
    version: i64,
) -> Result<(), EventStoreError> {
    match event {
        PackageRepositoryEvent::Created { organization_id, name, format, repo_type, remote_url, remote_username, remote_password, .. } => {
            sqlx::query!(
                "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, version, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now())",
                repository_id,
                organization_id,
                name,
                format_to_str(*format),
                repo_type_to_str(*repo_type),
                remote_url.as_deref(),
                remote_username.as_deref(),
                remote_password.as_deref(),
                version
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::Renamed { new_name, .. } => {
            sqlx::query!(
                "UPDATE package_repository_projections SET name = $1, version = $2, updated_at = now() WHERE id = $3",
                new_name,
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::RemoteUrlChanged { remote_url, .. } => {
            sqlx::query!(
                "UPDATE package_repository_projections SET remote_url = $1, version = $2, updated_at = now() WHERE id = $3",
                remote_url,
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::GroupMemberAdded { member_repository_id, position, .. } => {
            sqlx::query!(
                "INSERT INTO package_repository_group_members (group_repository_id, member_repository_id, position) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (group_repository_id, member_repository_id) DO UPDATE SET position = EXCLUDED.position",
                repository_id,
                member_repository_id,
                position
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
            sqlx::query!(
                "UPDATE package_repository_projections SET version = $1, updated_at = now() WHERE id = $2",
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::GroupMemberRemoved { member_repository_id, .. } => {
            sqlx::query!(
                "DELETE FROM package_repository_group_members WHERE group_repository_id = $1 AND member_repository_id = $2",
                repository_id,
                member_repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
            sqlx::query!(
                "UPDATE package_repository_projections SET version = $1, updated_at = now() WHERE id = $2",
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::QuotaSet { quota_bytes, .. } => {
            sqlx::query!(
                "UPDATE package_repository_projections SET quota_bytes = $1, version = $2, updated_at = now() WHERE id = $3",
                *quota_bytes,
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::RetentionPolicySet { keep_last_n_versions, .. } => {
            sqlx::query!(
                "UPDATE package_repository_projections SET retention_keep_last_n = $1, version = $2, updated_at = now() WHERE id = $3",
                *keep_last_n_versions,
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
        PackageRepositoryEvent::Deleted { .. } => {
            sqlx::query!(
                "UPDATE package_repository_projections SET deleted_at = now(), version = $1, updated_at = now() WHERE id = $2",
                version,
                repository_id
            )
            .execute(&mut **tx)
            .await
            .storage_err()?;
        }
    }
    Ok(())
}

#[async_trait]
impl PackageRepositoryQueryPort for PostgresPackageRepositoryStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        let row = sqlx::query!(
            "SELECT id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, quota_bytes, retention_keep_last_n FROM package_repository_projections WHERE id = $1 AND deleted_at IS NULL",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .storage_err()?;
        match row {
            Some(row) => Ok(Some(self.build_summary(row.id, row.organization_id, row.name, row.format, row.repo_type, row.remote_url, row.remote_username, row.remote_password, row.quota_bytes, row.retention_keep_last_n).await?)),
            None => Ok(None),
        }
    }

    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        let row = sqlx::query!(
            "SELECT id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, quota_bytes, retention_keep_last_n FROM package_repository_projections WHERE organization_id = $1 AND name = $2 AND deleted_at IS NULL",
            organization_id, name
        )
        .fetch_optional(&self.pool)
        .await
        .storage_err()?;
        match row {
            Some(row) => Ok(Some(self.build_summary(row.id, row.organization_id, row.name, row.format, row.repo_type, row.remote_url, row.remote_username, row.remote_password, row.quota_bytes, row.retention_keep_last_n).await?)),
            None => Ok(None),
        }
    }

    async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
        let rows = sqlx::query!(
            "SELECT id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, quota_bytes, retention_keep_last_n FROM package_repository_projections WHERE deleted_at IS NULL"
        )
        .fetch_all(&self.pool)
        .await
        .storage_err()?;

        // One batched query for every repository's group members, not one per row.
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        let member_rows = sqlx::query!(
            "SELECT group_repository_id, member_repository_id FROM package_repository_group_members \
             WHERE group_repository_id = ANY($1) ORDER BY group_repository_id, position",
            &ids
        )
        .fetch_all(&self.pool)
        .await
        .storage_err()?;
        let mut members_by_group: std::collections::HashMap<Uuid, Vec<Uuid>> = std::collections::HashMap::new();
        for row in member_rows {
            members_by_group.entry(row.group_repository_id).or_default().push(row.member_repository_id);
        }

        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            summaries.push(PackageRepositorySummary {
                id: row.id,
                organization_id: row.organization_id,
                name: row.name,
                format: format_from_str(&row.format).ok_or_else(|| EventStoreError::Storage(format!("unknown format {}", row.format)))?,
                repo_type: repo_type_from_str(&row.repo_type).ok_or_else(|| EventStoreError::Storage(format!("unknown repo_type {}", row.repo_type)))?,
                remote_url: row.remote_url,
                remote_username: row.remote_username,
                remote_password: row.remote_password.map(|pw| secret_box::decrypt_packed(&pw, &self.secrets_encryption_key)),
                group_members: members_by_group.remove(&row.id).unwrap_or_default(),
                quota_bytes: row.quota_bytes,
                retention_keep_last_n: row.retention_keep_last_n,
            });
        }
        Ok(summaries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn creates_and_finds_a_repository(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        let event = PackageRepositoryEvent::Created {
            repository_id: id,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            name: "my-repo".to_string(),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
        };
        store.append(id, 0, vec![event], Uuid::new_v4()).await.unwrap();

        let summary = store.find_by_org_and_name(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo").await.unwrap().unwrap();
        assert_eq!(summary.id, id);
        assert_eq!(summary.repo_type, RepositoryType::Hosted);
    }

    #[sqlx::test]
    async fn a_proxy_repositorys_remote_password_round_trips_through_find_and_through_load(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        store
            .append(
                id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "proxy-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Proxy,
                    remote_url: Some("https://registry.npmjs.org".to_string()),
                    remote_username: Some("svc-account".to_string()),
                    remote_password: Some("s3cret-upstream-token".to_string()),
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();

        let summary = store.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(summary.remote_password.as_deref(), Some("s3cret-upstream-token"));

        let (_, events) = store.load(id).await.unwrap();
        assert!(matches!(&events[0], PackageRepositoryEvent::Created { remote_password: Some(pw), .. } if pw == "s3cret-upstream-token"));
    }

    #[sqlx::test]
    async fn the_remote_password_is_never_stored_in_plaintext(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        store
            .append(
                id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "proxy-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Proxy,
                    remote_url: Some("https://registry.npmjs.org".to_string()),
                    remote_username: Some("svc-account".to_string()),
                    remote_password: Some("s3cret-upstream-token".to_string()),
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();

        let projection_row: (Option<String>,) =
            sqlx::query_as("SELECT remote_password FROM package_repository_projections WHERE id = $1").bind(id).fetch_one(&store.pool).await.unwrap();
        assert!(!projection_row.0.unwrap().contains("s3cret-upstream-token"), "the plaintext password must never appear in the projection row");

        let event_row: (serde_json::Value,) =
            sqlx::query_as("SELECT payload FROM domain_events WHERE aggregate_type = 'PackageRepository' AND aggregate_id = $1").bind(id.to_string()).fetch_one(&store.pool).await.unwrap();
        assert!(!event_row.0.to_string().contains("s3cret-upstream-token"), "the plaintext password must never appear in the event journal");
    }

    #[sqlx::test]
    async fn a_deleted_repositorys_name_can_be_reused(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let first_id = Uuid::new_v4();
        store
            .append(
                first_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: first_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "recyclable".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        store
            .append(first_id, 1, vec![PackageRepositoryEvent::Deleted { repository_id: first_id }], Uuid::new_v4())
            .await
            .unwrap();
        assert!(store.find_by_org_and_name(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "recyclable").await.unwrap().is_none());

        let second_id = Uuid::new_v4();
        store
            .append(
                second_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: second_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "recyclable".to_string(),
                    format: RepositoryFormat::Docker,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();

        let summary = store.find_by_org_and_name(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "recyclable").await.unwrap().unwrap();
        assert_eq!(summary.id, second_id);
    }

    #[sqlx::test]
    async fn two_live_repositories_still_cannot_share_a_name(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let first_id = Uuid::new_v4();
        store
            .append(
                first_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: first_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "exclusive".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();

        let second_id = Uuid::new_v4();
        let result = store
            .append(
                second_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: second_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "exclusive".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await;

        assert!(result.is_err());
    }

    #[sqlx::test]
    async fn adding_a_group_member_is_reflected_in_the_summary(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let group_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        store
            .append(
                group_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: group_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "group-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Group,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        // A member must be a real repository row — member_repository_id is FK-constrained.
        store
            .append(
                member_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: member_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "member-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        store
            .append(
                group_id,
                1,
                vec![PackageRepositoryEvent::GroupMemberAdded { repository_id: group_id, member_repository_id: member_id, position: 0 }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();

        let summary = store.find_by_id(group_id).await.unwrap().unwrap();
        assert_eq!(summary.group_members, vec![member_id]);
    }

    #[sqlx::test]
    async fn list_all_batches_group_members_across_every_repository(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let group_a = Uuid::new_v4();
        let group_b = Uuid::new_v4();
        let member_a = Uuid::new_v4();
        let member_b = Uuid::new_v4();
        for (group_id, name) in [(group_a, "group-a"), (group_b, "group-b")] {
            store
                .append(
                    group_id,
                    0,
                    vec![PackageRepositoryEvent::Created {
                        repository_id: group_id,
                        organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                        name: name.to_string(),
                        format: RepositoryFormat::Npm,
                        repo_type: RepositoryType::Group,
                        remote_url: None,
                        remote_username: None,
                        remote_password: None,
                    }],
                    Uuid::new_v4(),
                )
                .await
                .unwrap();
        }
        // A member must be a real repository row — member_repository_id is FK-constrained.
        for (member_id, name) in [(member_a, "member-a"), (member_b, "member-b")] {
            store
                .append(
                    member_id,
                    0,
                    vec![PackageRepositoryEvent::Created {
                        repository_id: member_id,
                        organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                        name: name.to_string(),
                        format: RepositoryFormat::Npm,
                        repo_type: RepositoryType::Hosted,
                        remote_url: None,
                        remote_username: None,
                        remote_password: None,
                    }],
                    Uuid::new_v4(),
                )
                .await
                .unwrap();
        }
        store.append(group_a, 1, vec![PackageRepositoryEvent::GroupMemberAdded { repository_id: group_a, member_repository_id: member_a, position: 0 }], Uuid::new_v4()).await.unwrap();
        store.append(group_b, 1, vec![PackageRepositoryEvent::GroupMemberAdded { repository_id: group_b, member_repository_id: member_b, position: 0 }], Uuid::new_v4()).await.unwrap();

        let all = store.list_all().await.unwrap();

        assert_eq!(all.iter().find(|r| r.id == group_a).unwrap().group_members, vec![member_a]);
        assert_eq!(all.iter().find(|r| r.id == group_b).unwrap().group_members, vec![member_b]);
    }

    #[sqlx::test]
    async fn setting_a_quota_is_reflected_in_the_summary(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        store
            .append(
                id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "quota-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, None, "unset by default");

        store.append(id, 1, vec![PackageRepositoryEvent::QuotaSet { repository_id: id, quota_bytes: Some(1024) }], Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, Some(1024));

        store.append(id, 2, vec![PackageRepositoryEvent::QuotaSet { repository_id: id, quota_bytes: None }], Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, None, "clearing the quota restores unlimited");
    }

    #[sqlx::test]
    async fn setting_a_retention_policy_is_reflected_in_the_summary(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        store
            .append(
                id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "retention-repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, None, "unset by default");

        store.append(id, 1, vec![PackageRepositoryEvent::RetentionPolicySet { repository_id: id, keep_last_n_versions: Some(3) }], Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, Some(3));

        store.append(id, 2, vec![PackageRepositoryEvent::RetentionPolicySet { repository_id: id, keep_last_n_versions: None }], Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, None, "clearing disables the policy again");
    }

    #[sqlx::test]
    async fn deleting_hides_the_repository_from_list_all(pool: sqlx::PgPool) {
        let store = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let id = Uuid::new_v4();
        store
            .append(
                id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id: id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "to-delete".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        store.append(id, 1, vec![PackageRepositoryEvent::Deleted { repository_id: id }], Uuid::new_v4()).await.unwrap();

        assert!(store.list_all().await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn serializes_concurrent_first_appends_for_a_new_aggregate(pool: sqlx::PgPool) {
        let store_a = PostgresPackageRepositoryStore::new(pool.clone(), "test-secret".to_string());
        let store_b = PostgresPackageRepositoryStore::new(pool, "test-secret".to_string());
        let repository_id = Uuid::new_v4();

        let (result_a, result_b) = tokio::join!(
            store_a.append(
                repository_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "race-repo-a".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4()
            ),
            store_b.append(
                repository_id,
                0,
                vec![PackageRepositoryEvent::Created {
                    repository_id,
                    organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
                    name: "race-repo-b".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                }],
                Uuid::new_v4()
            )
        );

        let outcomes = [result_a, result_b];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        let conflicts = outcomes.iter().filter(|r| matches!(r, Err(EventStoreError::ConcurrencyConflict { expected: 0, actual: 1 }))).count();

        assert_eq!(successes, 1, "expected exactly one append to succeed, got: {outcomes:?}");
        assert_eq!(conflicts, 1, "expected the loser to get a clean ConcurrencyConflict{{expected:0, actual:1}}, got: {outcomes:?}");
    }
}
