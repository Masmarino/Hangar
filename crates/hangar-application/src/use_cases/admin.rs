use std::sync::Arc;

use chrono::{DateTime, Utc};
use hangar_domain::audit::{AuditEntry, AuditQueryFilter, EventPublisherPort, SecurityEvent};
use hangar_domain::docker_registry::DockerBlobStorePort;
use hangar_domain::health::{ComponentHealth, DatabaseHealth, HealthCheckPort};
use hangar_domain::metrics_snapshot::{MetricsSnapshot, MetricsSnapshotRepositoryPort};
use hangar_domain::organization::OrganizationRepositoryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, RepositoryFormat, RepositoryType};
use hangar_domain::permission::{PermissionQueryPort, Role};
use hangar_domain::storage::StorageBackendPort;
use hangar_domain::system_settings::{SystemSettings, SystemSettingsPort};
use hangar_domain::user::UserRepositoryPort;
use std::time::Instant;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct QueryAuditLogUseCase {
    publisher: Arc<dyn EventPublisherPort>,
}

impl QueryAuditLogUseCase {
    pub fn new(publisher: Arc<dyn EventPublisherPort>) -> Self {
        Self { publisher }
    }

    pub async fn execute(&self, filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, ApplicationError> {
        Ok(self.publisher.query_audit_log(filter).await?)
    }
}

pub struct RecordSecurityEventUseCase {
    publisher: Arc<dyn EventPublisherPort>,
}

impl RecordSecurityEventUseCase {
    pub fn new(publisher: Arc<dyn EventPublisherPort>) -> Self {
        Self { publisher }
    }

    pub async fn execute(&self, event: SecurityEvent, actor_id: Option<Uuid>) -> Result<(), ApplicationError> {
        Ok(self.publisher.publish_security_event(event, actor_id).await?)
    }
}

#[derive(Debug, Clone)]
pub struct RepositoryUsage {
    pub repository_id: Uuid,
    pub name: String,
    pub used_bytes: u64,
    /// `None` means unlimited.
    pub quota_bytes: Option<i64>,
}

pub struct GetUsageMetricsUseCase {
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    storage: Arc<dyn StorageBackendPort>,
    docker_blobs: Arc<dyn DockerBlobStorePort>,
}

impl GetUsageMetricsUseCase {
    pub fn new(
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        storage: Arc<dyn StorageBackendPort>,
        docker_blobs: Arc<dyn DockerBlobStorePort>,
    ) -> Self {
        Self { repositories, storage, docker_blobs }
    }

    pub async fn execute(&self) -> Result<Vec<RepositoryUsage>, ApplicationError> {
        let repos = self.repositories.list_all().await?;

        let docker_ids: Vec<Uuid> = repos.iter().filter(|r| r.format == RepositoryFormat::Docker).map(|r| r.id).collect();
        // Docker blobs are content-addressed and deduped globally, not per-repository — one batched query for all of them.
        let docker_usage = self.docker_blobs.used_bytes_for_repositories(&docker_ids).await?;

        let npm_repos: Vec<_> = repos.iter().filter(|r| r.format == RepositoryFormat::Npm).collect();
        let npm_bytes = futures::future::try_join_all(npm_repos.iter().map(|r| self.storage.used_bytes(r.id))).await?;
        let npm_usage: std::collections::HashMap<Uuid, u64> = npm_repos.iter().map(|r| r.id).zip(npm_bytes).collect();

        let usages = repos
            .into_iter()
            .map(|repo| {
                let used_bytes = match repo.format {
                    RepositoryFormat::Npm => npm_usage.get(&repo.id).copied().unwrap_or(0),
                    RepositoryFormat::Docker => docker_usage.get(&repo.id).copied().unwrap_or(0),
                };
                RepositoryUsage { repository_id: repo.id, name: repo.name, used_bytes, quota_bytes: repo.quota_bytes }
            })
            .collect();
        Ok(usages)
    }
}

/// Called periodically (see main.rs's timer) so the admin UI can chart totals over time.
pub struct RecordMetricsSnapshotUseCase {
    users: Arc<dyn UserRepositoryPort>,
    usage_metrics: Arc<GetUsageMetricsUseCase>,
    snapshots: Arc<dyn MetricsSnapshotRepositoryPort>,
}

impl RecordMetricsSnapshotUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, usage_metrics: Arc<GetUsageMetricsUseCase>, snapshots: Arc<dyn MetricsSnapshotRepositoryPort>) -> Self {
        Self { users, usage_metrics, snapshots }
    }

    pub async fn execute(&self) -> Result<(), ApplicationError> {
        let total_users = self.users.list_all().await?.len() as i64;
        let usages = self.usage_metrics.execute().await?;
        let total_repositories = usages.len() as i64;
        let total_storage_bytes = usages.iter().map(|u| u.used_bytes as i64).sum();
        let snapshot = MetricsSnapshot {
            id: Uuid::new_v4(),
            recorded_at: Utc::now(),
            total_users,
            total_repositories,
            total_storage_bytes,
        };
        self.snapshots.save(&snapshot).await?;
        Ok(())
    }
}

pub struct GetMetricsHistoryUseCase {
    snapshots: Arc<dyn MetricsSnapshotRepositoryPort>,
}

impl GetMetricsHistoryUseCase {
    pub fn new(snapshots: Arc<dyn MetricsSnapshotRepositoryPort>) -> Self {
        Self { snapshots }
    }

    pub async fn execute(&self, since: DateTime<Utc>) -> Result<Vec<MetricsSnapshot>, ApplicationError> {
        Ok(self.snapshots.list_since(since).await?)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StorageHealth {
    pub status: ComponentHealth,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthStatus {
    pub database: DatabaseHealth,
    pub storage: StorageHealth,
    pub uptime_seconds: u64,
}

pub struct GetHealthStatusUseCase {
    database: Arc<dyn HealthCheckPort>,
    storage: Arc<dyn StorageBackendPort>,
    started_at: Instant,
}

impl GetHealthStatusUseCase {
    pub fn new(database: Arc<dyn HealthCheckPort>, storage: Arc<dyn StorageBackendPort>, started_at: Instant) -> Self {
        Self { database, storage, started_at }
    }

    pub async fn execute(&self) -> HealthStatus {
        let database = self.database.check().await;

        let storage_up = self.storage.is_healthy().await;
        // Disk space is informational; failing to read it degrades to zeroes, not down.
        let space = self.storage.volume_space().await.unwrap_or(hangar_domain::storage::VolumeSpace { total_bytes: 0, free_bytes: 0 });
        let storage = StorageHealth {
            status: if storage_up { ComponentHealth::Up } else { ComponentHealth::Down("storage backend unreachable".to_string()) },
            used_bytes: space.total_bytes.saturating_sub(space.free_bytes),
            free_bytes: space.free_bytes,
            total_bytes: space.total_bytes,
        };

        HealthStatus { database, storage, uptime_seconds: self.started_at.elapsed().as_secs() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminStats {
    pub total_users: usize,
    pub total_repositories: usize,
    pub total_active_permissions: usize,
}

pub struct GetAdminStatsUseCase {
    users: Arc<dyn UserRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    permissions: Arc<dyn PermissionQueryPort>,
}

impl GetAdminStatsUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, repositories: Arc<dyn PackageRepositoryQueryPort>, permissions: Arc<dyn PermissionQueryPort>) -> Self {
        Self { users, repositories, permissions }
    }

    pub async fn execute(&self) -> Result<AdminStats, ApplicationError> {
        let total_users = self.users.list_all().await?.len();
        let total_repositories = self.repositories.list_all().await?.len();
        let total_active_permissions = self.permissions.count_all().await?;
        Ok(AdminStats { total_users, total_repositories, total_active_permissions })
    }
}

#[derive(Debug, Clone)]
pub struct AdminApiTokenEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    /// `None` for a token whose owning user no longer exists — only a super-admin can manage such a token.
    pub organization_id: Option<Uuid>,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct AdminListApiTokensUseCase {
    tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort>,
    users: Arc<dyn UserRepositoryPort>,
}

impl AdminListApiTokensUseCase {
    pub fn new(tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort>, users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { tokens, users }
    }

    /// An orphaned token is surfaced with a placeholder username rather than dropped.
    pub async fn execute(&self) -> Result<Vec<AdminApiTokenEntry>, ApplicationError> {
        let tokens = self.tokens.list_all().await?;
        let users = self.users.list_all().await?;
        let user_by_id: std::collections::HashMap<Uuid, &hangar_domain::user::User> = users.iter().map(|u| (u.id, u)).collect();
        Ok(tokens
            .into_iter()
            .map(|t| {
                let user = user_by_id.get(&t.user_id);
                let username = user.map(|u| u.username.as_str().to_string()).unwrap_or_else(|| "(utilisateur supprimé)".to_string());
                let organization_id = user.map(|u| u.organization_id);
                AdminApiTokenEntry { id: t.id, user_id: t.user_id, username, organization_id, label: t.label, created_at: t.created_at, last_used_at: t.last_used_at, revoked_at: t.revoked_at }
            })
            .collect())
    }
}

pub struct AdminRevokeApiTokenUseCase {
    tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort>,
}

impl AdminRevokeApiTokenUseCase {
    pub fn new(tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort>) -> Self {
        Self { tokens }
    }

    pub async fn execute(&self, token_id: Uuid) -> Result<(), ApplicationError> {
        Ok(self.tokens.revoke_any(token_id).await?)
    }
}

pub struct GetSystemSettingsUseCase {
    settings: Arc<dyn SystemSettingsPort>,
}

impl GetSystemSettingsUseCase {
    pub fn new(settings: Arc<dyn SystemSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: Uuid) -> Result<SystemSettings, ApplicationError> {
        Ok(self.settings.get(organization_id).await?)
    }
}

pub struct UpdateSystemSettingsUseCase {
    settings: Arc<dyn SystemSettingsPort>,
}

impl UpdateSystemSettingsUseCase {
    pub fn new(settings: Arc<dyn SystemSettingsPort>) -> Self {
        Self { settings }
    }

    /// The only place these ranges are validated — downstream consumers trust their inputs.
    pub async fn execute(&self, organization_id: Uuid, settings: SystemSettings) -> Result<(), ApplicationError> {
        if !(1..=1000).contains(&settings.max_login_attempts) {
            return Err(ApplicationError::InvalidSystemSettings("max_login_attempts must be between 1 and 1000".to_string()));
        }
        if !(1..=86_400).contains(&settings.login_attempt_window_seconds) {
            return Err(ApplicationError::InvalidSystemSettings("login_attempt_window_seconds must be between 1 and 86400 (24h)".to_string()));
        }
        if !(1..=720).contains(&settings.session_ttl_hours) {
            return Err(ApplicationError::InvalidSystemSettings("session_ttl_hours must be between 1 and 720 (30 days)".to_string()));
        }
        self.settings.update(organization_id, &settings).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExportedUser {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub created_at: DateTime<Utc>,
    pub email: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExportedRepository {
    pub id: Uuid,
    pub name: String,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub remote_url: Option<String>,
    pub remote_username: Option<String>,
    pub remote_password: Option<String>,
    pub group_members: Vec<Uuid>,
    pub quota_bytes: Option<i64>,
    pub retention_keep_last_n: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExportedPermission {
    pub user_id: Uuid,
    pub repository_id: Uuid,
    pub role: Role,
}

/// No packages/images (too large) and no credentials — this file gets downloaded to disk.
#[derive(Debug, Clone)]
pub struct ConfigurationExport {
    pub exported_at: DateTime<Utc>,
    pub users: Vec<ExportedUser>,
    pub repositories: Vec<ExportedRepository>,
    pub permissions: Vec<ExportedPermission>,
    pub system_settings: SystemSettings,
}

pub struct ExportConfigurationUseCase {
    users: Arc<dyn UserRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    permissions: Arc<dyn PermissionQueryPort>,
    system_settings: Arc<dyn SystemSettingsPort>,
}

impl ExportConfigurationUseCase {
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        permissions: Arc<dyn PermissionQueryPort>,
        system_settings: Arc<dyn SystemSettingsPort>,
    ) -> Self {
        Self { users, repositories, permissions, system_settings }
    }

    pub async fn execute(&self) -> Result<ConfigurationExport, ApplicationError> {
        let users = self.users.list_all().await?;
        let repositories = self.repositories.list_all().await?;

        let permissions: Vec<ExportedPermission> = self
            .permissions
            .list_all()
            .await?
            .into_iter()
            .map(|(user_id, repository_id, role)| ExportedPermission { user_id, repository_id, role })
            .collect();

        // Known asymmetry, not a bug: always reads the public organization's settings, while
        // import restores into the acting super-admin's own org (see restore_organization_id below).
        let system_settings = self.system_settings.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await?;

        Ok(ConfigurationExport {
            exported_at: Utc::now(),
            users: users
                .into_iter()
                .map(|u| ExportedUser { id: u.id, username: u.username.as_str().to_string(), is_super_admin: u.is_super_admin, created_at: u.created_at, email: u.email })
                .collect(),
            repositories: repositories
                .into_iter()
                .map(|r| ExportedRepository {
                    id: r.id,
                    name: r.name,
                    format: r.format,
                    repo_type: r.repo_type,
                    remote_url: r.remote_url,
                    // Never exported — see ImportReport.proxy_credentials_needed on the import side.
                    remote_username: None,
                    remote_password: None,
                    group_members: r.group_members,
                    quota_bytes: r.quota_bytes,
                    retention_keep_last_n: r.retention_keep_last_n,
                })
                .collect(),
            permissions,
            system_settings,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConfigurationImport {
    pub users: Vec<ExportedUser>,
    pub repositories: Vec<ExportedRepository>,
    pub permissions: Vec<ExportedPermission>,
    pub system_settings: SystemSettings,
}

#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    pub users_created: usize,
    pub repositories_created: usize,
    pub permissions_granted: usize,
    pub invited: Vec<String>,
    pub skipped_no_email: Vec<String>,
    pub failed: Vec<String>,
    /// Proxy repos restored without credentials — expected, since export never includes them.
    pub proxy_credentials_needed: Vec<String>,
}

pub struct ImportConfigurationUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn hangar_domain::user::PasswordHasherPort>,
    create_repository: Arc<crate::use_cases::package_repository::CreatePackageRepositoryUseCase>,
    set_quota: Arc<crate::use_cases::package_repository::SetRepositoryQuotaUseCase>,
    set_retention: Arc<crate::use_cases::package_repository::SetRetentionPolicyUseCase>,
    add_group_member: Arc<crate::use_cases::package_repository::AddGroupMemberUseCase>,
    grant_permission: Arc<crate::use_cases::permission::GrantPermissionUseCase>,
    update_settings: Arc<UpdateSystemSettingsUseCase>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    invitations: Arc<dyn hangar_domain::invitation::UserInvitationPort>,
    email: Arc<dyn hangar_domain::email::EmailPort>,
    organizations: Arc<dyn OrganizationRepositoryPort>,
    /// No trailing slash. See `crate::use_cases::invitation::organization_origin`.
    hangar_base_domain: String,
}

impl ImportConfigurationUseCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        hasher: Arc<dyn hangar_domain::user::PasswordHasherPort>,
        create_repository: Arc<crate::use_cases::package_repository::CreatePackageRepositoryUseCase>,
        set_quota: Arc<crate::use_cases::package_repository::SetRepositoryQuotaUseCase>,
        set_retention: Arc<crate::use_cases::package_repository::SetRetentionPolicyUseCase>,
        add_group_member: Arc<crate::use_cases::package_repository::AddGroupMemberUseCase>,
        grant_permission: Arc<crate::use_cases::permission::GrantPermissionUseCase>,
        update_settings: Arc<UpdateSystemSettingsUseCase>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        invitations: Arc<dyn hangar_domain::invitation::UserInvitationPort>,
        email: Arc<dyn hangar_domain::email::EmailPort>,
        organizations: Arc<dyn OrganizationRepositoryPort>,
        hangar_base_domain: String,
    ) -> Self {
        Self { users, hasher, create_repository, set_quota, set_retention, add_group_member, grant_permission, update_settings, repositories, invitations, email, organizations, hangar_base_domain }
    }

    pub async fn execute(&self, import: ConfigurationImport, actor_id: Uuid) -> Result<ImportReport, ApplicationError> {
        // Guard: instance must be empty except for the caller.
        if !self.repositories.list_all().await?.is_empty() {
            return Err(ApplicationError::InstanceNotEmpty);
        }
        let existing_users = self.users.list_all().await?;
        if existing_users.iter().any(|u| u.id != actor_id) {
            return Err(ApplicationError::InstanceNotEmpty);
        }
        // Restored users join the acting admin's own organization — the export carries no organization of its own.
        let restore_organization_id = existing_users
            .iter()
            .find(|u| u.id == actor_id)
            .map(|u| u.organization_id)
            .ok_or(ApplicationError::ActingAdminNotFound)?;
        let restore_organization = crate::use_cases::invitation::require_organization(self.organizations.as_ref(), restore_organization_id).await?;
        let activation_origin = crate::use_cases::invitation::organization_origin(&self.hangar_base_domain, &restore_organization);

        let mut report = ImportReport::default();

        // Users actually inserted — permission/invitation loops below gate on this, not import.users.
        let mut restored_user_ids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

        // Users: ids preserved exactly, unusable password until invited.
        for exported in &import.users {
            let username = match hangar_domain::user::Username::parse(&exported.username) {
                Ok(u) => u,
                Err(e) => { report.failed.push(format!("user {}: {e}", exported.username)); continue; }
            };
            match self.users.find_by_username(&username).await {
                Ok(Some(_)) => {
                    report.failed.push(format!("user {}: username already taken by the signed-in account", exported.username));
                    continue;
                }
                Ok(None) => {}
                Err(e) => { report.failed.push(format!("user {}: {e}", exported.username)); continue; }
            }
            let password_hash = match crate::use_cases::invitation::unusable_password_hash(self.hasher.as_ref()).await {
                Ok(hash) => hash,
                Err(e) => { report.failed.push(format!("user {}: {e}", exported.username)); continue; }
            };
            let user = hangar_domain::user::User {
                id: exported.id,
                username,
                password_hash,
                is_super_admin: exported.is_super_admin,
                is_organization_admin: false,
                organization_id: restore_organization_id,
                created_at: exported.created_at,
                tokens_valid_after: exported.created_at,
                email: exported.email.clone(),
            };
            match self.users.insert(&user).await {
                Ok(()) => {
                    report.users_created += 1;
                    restored_user_ids.insert(exported.id);
                }
                Err(e) => report.failed.push(format!("user {}: {e}", exported.username)),
            }
        }

        // Repositories, pass 1: create, building old_id -> new_id.
        let mut repo_id_map: std::collections::HashMap<Uuid, Uuid> = std::collections::HashMap::new();
        for exported in &import.repositories {
            match self
                .create_repository
                .execute(restore_organization_id, &exported.name, exported.format, exported.repo_type, exported.remote_url.clone(), exported.remote_username.clone(), exported.remote_password.clone(), actor_id)
                .await
            {
                Ok(new_id) => {
                    repo_id_map.insert(exported.id, new_id);
                    report.repositories_created += 1;
                    if exported.repo_type == RepositoryType::Proxy && exported.remote_username.is_none() && exported.remote_password.is_none() {
                        report.proxy_credentials_needed.push(exported.name.clone());
                    }
                }
                Err(e) => report.failed.push(format!("repository {}: {e}", exported.name)),
            }
        }

        // Repositories, pass 2: quota/retention.
        for exported in &import.repositories {
            let Some(&new_id) = repo_id_map.get(&exported.id) else { continue };
            if exported.quota_bytes.is_some() {
                if let Err(e) = self.set_quota.execute(new_id, exported.quota_bytes, actor_id).await {
                    report.failed.push(format!("repository {} quota: {e}", exported.name));
                }
            }
            if exported.retention_keep_last_n.is_some() {
                if let Err(e) = self.set_retention.execute(new_id, exported.retention_keep_last_n, actor_id).await {
                    report.failed.push(format!("repository {} retention: {e}", exported.name));
                }
            }
        }

        // Repositories, pass 3: group members — needs every repo to exist first.
        for exported in &import.repositories {
            let Some(&new_group_id) = repo_id_map.get(&exported.id) else { continue };
            for (position, old_member_id) in exported.group_members.iter().enumerate() {
                let Some(&new_member_id) = repo_id_map.get(old_member_id) else {
                    report.failed.push(format!("repository {}: group member {old_member_id} was never created", exported.name));
                    continue;
                };
                if let Err(e) = self.add_group_member.execute(new_group_id, new_member_id, position as i32, actor_id).await {
                    report.failed.push(format!("repository {} group member: {e}", exported.name));
                }
            }
        }

        // Permissions.
        for exported in &import.permissions {
            if !restored_user_ids.contains(&exported.user_id) {
                report.failed.push(format!("permission for {}: user was never restored", exported.user_id));
                continue;
            }
            let Some(&new_repo_id) = repo_id_map.get(&exported.repository_id) else {
                report.failed.push(format!("permission for {}: repository {} was never created", exported.user_id, exported.repository_id));
                continue;
            };
            match self.grant_permission.execute(exported.user_id, new_repo_id, exported.role, actor_id).await {
                Ok(()) => report.permissions_granted += 1,
                Err(e) => report.failed.push(format!("permission for {}: {e}", exported.user_id)),
            }
        }

        // System settings.
        if let Err(e) = self.update_settings.execute(restore_organization_id, import.system_settings).await {
            report.failed.push(format!("system settings: {e}"));
        }

        // Invitations, best-effort. Skips users that were never restored.
        for exported in &import.users {
            if !restored_user_ids.contains(&exported.id) {
                continue;
            }
            let Some(email) = exported.email.as_deref() else {
                report.skipped_no_email.push(exported.username.clone());
                continue;
            };
            let token = crate::use_cases::invitation::generate_invitation_token();
            let invitation = hangar_domain::invitation::UserInvitation {
                user_id: exported.id,
                token_hash: crate::use_cases::invitation::hash_invitation_token(&token),
                expires_at: Utc::now() + chrono::Duration::hours(crate::use_cases::invitation::INVITATION_TTL_HOURS),
            };
            if let Err(e) = self.invitations.upsert(&invitation).await {
                report.failed.push(format!("invitation for {}: {e}", exported.username));
                continue;
            }
            let activation_url = format!("{activation_origin}/activate?token={token}");
            let content = crate::email_templates::account_created(&exported.username, &activation_url);
            match self.email.send(restore_organization_id, email, &content.subject, &content.text, &content.html).await {
                Ok(()) => report.invited.push(exported.username.clone()),
                Err(e) => report.failed.push(format!("invitation email for {}: {e}", exported.username)),
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hangar_domain::api_token::ApiTokenRepositoryPort;
    use hangar_domain::error::{DomainError, EventStoreError};
    use hangar_domain::organization::{Organization, OrganizationSlug};
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
    use hangar_domain::permission::Role;
    use hangar_domain::storage::StorageError;
    use hangar_domain::user::{User, Username};
    use crate::use_cases::package_repository::{AddGroupMemberUseCase, CreatePackageRepositoryUseCase, SetRepositoryQuotaUseCase, SetRetentionPolicyUseCase};
    use crate::use_cases::permission::GrantPermissionUseCase;
    use hangar_domain::invitation::UserInvitationPort;
    use hangar_domain::permission::PermissionEventStorePort;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::Arc;

    struct FakeUsers {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl FakeUsers {
        fn seeded(users: Vec<User>) -> Self {
            Self { users: Mutex::new(users.into_iter().map(|u| (u.id, u)).collect()) }
        }
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| &u.username == username).cloned())
        }
        async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some(email)).cloned())
        }
        async fn list_all(&self) -> Result<Vec<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().cloned().collect())
        }
        async fn insert(&self, user: &User) -> Result<(), DomainError> {
            self.users.lock().unwrap().insert(user.id, user.clone());
            Ok(())
        }
        async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(())
        }
        async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.password_hash = new_password_hash;
            }
            Ok(())
        }
        async fn set_super_admin(&self, id: Uuid, is_super_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(())
        }
        async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_organization_admin = is_organization_admin;
            }
            Ok(())
        }
        async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(true)
        }
        async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(true)
        }
    }

    struct FakePackageRepositoryStore {
        streams: Mutex<HashMap<Uuid, Vec<hangar_domain::package_repository::PackageRepositoryEvent>>>,
    }

    impl FakePackageRepositoryStore {
        fn new() -> Self {
            Self { streams: Mutex::new(HashMap::new()) }
        }

        fn summarize(id: Uuid, events: &[hangar_domain::package_repository::PackageRepositoryEvent]) -> Option<PackageRepositorySummary> {
            let repo = hangar_domain::package_repository::PackageRepository::from_events(events);
            if repo.deleted || repo.name.is_none() {
                return None;
            }
            // The aggregate itself doesn't track organization_id, so pull it from the Created
            // event, mirroring how the real Postgres projection persists it as its own column.
            let organization_id = events
                .iter()
                .find_map(|event| match event {
                    hangar_domain::package_repository::PackageRepositoryEvent::Created { organization_id, .. } => Some(*organization_id),
                    _ => None,
                })
                .expect("a summarizable repository always has a Created event");
            Some(PackageRepositorySummary {
                id,
                organization_id,
                name: repo.name.unwrap(),
                format: repo.format.unwrap(),
                repo_type: repo.repo_type.unwrap(),
                remote_url: repo.remote_url,
                remote_username: repo.remote_username,
                remote_password: repo.remote_password,
                group_members: repo.group_members.into_iter().map(|(id, _)| id).collect(),
                quota_bytes: repo.quota_bytes,
                retention_keep_last_n: repo.retention_keep_last_n,
            })
        }
    }

    #[async_trait]
    impl hangar_domain::package_repository::PackageRepositoryEventStorePort for FakePackageRepositoryStore {
        async fn load(&self, repository_id: Uuid) -> Result<(u64, Vec<hangar_domain::package_repository::PackageRepositoryEvent>), EventStoreError> {
            let streams = self.streams.lock().unwrap();
            let events = streams.get(&repository_id).cloned().unwrap_or_default();
            Ok((events.len() as u64, events))
        }

        async fn append(
            &self,
            repository_id: Uuid,
            expected_version: u64,
            events: Vec<hangar_domain::package_repository::PackageRepositoryEvent>,
            _actor_id: Uuid,
        ) -> Result<(), EventStoreError> {
            let mut streams = self.streams.lock().unwrap();
            let stream = streams.entry(repository_id).or_default();
            if stream.len() as u64 != expected_version {
                return Err(EventStoreError::ConcurrencyConflict { expected: expected_version, actual: stream.len() as u64 });
            }
            stream.extend(events);
            Ok(())
        }
    }

    #[async_trait]
    impl PackageRepositoryQueryPort for FakePackageRepositoryStore {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams.get(&id).and_then(|events| Self::summarize(id, events)))
        }
        async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams
                .iter()
                .find_map(|(id, events)| Self::summarize(*id, events).filter(|s| s.organization_id == organization_id && s.name == name)))
        }
        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams.iter().filter_map(|(id, events)| Self::summarize(*id, events)).collect())
        }
    }

    struct FakePermissionStore {
        streams: Mutex<HashMap<(Uuid, Uuid), Vec<hangar_domain::permission::PermissionEvent>>>,
    }

    impl FakePermissionStore {
        fn new() -> Self {
            Self { streams: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl hangar_domain::permission::PermissionEventStorePort for FakePermissionStore {
        async fn load(&self, user_id: Uuid, repository_id: Uuid) -> Result<(u64, Vec<hangar_domain::permission::PermissionEvent>), EventStoreError> {
            let streams = self.streams.lock().unwrap();
            let events = streams.get(&(user_id, repository_id)).cloned().unwrap_or_default();
            Ok((events.len() as u64, events))
        }
        async fn append(
            &self,
            user_id: Uuid,
            repository_id: Uuid,
            expected_version: u64,
            events: Vec<hangar_domain::permission::PermissionEvent>,
            _actor_id: Uuid,
        ) -> Result<(), EventStoreError> {
            let mut streams = self.streams.lock().unwrap();
            let stream = streams.entry((user_id, repository_id)).or_default();
            if stream.len() as u64 != expected_version {
                return Err(EventStoreError::ConcurrencyConflict { expected: expected_version, actual: stream.len() as u64 });
            }
            stream.extend(events);
            Ok(())
        }
    }

    struct FakeInvitations {
        by_user: Mutex<HashMap<Uuid, hangar_domain::invitation::UserInvitation>>,
    }

    impl FakeInvitations {
        fn new() -> Self {
            Self { by_user: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl hangar_domain::invitation::UserInvitationPort for FakeInvitations {
        async fn upsert(&self, invitation: &hangar_domain::invitation::UserInvitation) -> Result<(), DomainError> {
            self.by_user.lock().unwrap().insert(invitation.user_id, invitation.clone());
            Ok(())
        }
        async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<hangar_domain::invitation::UserInvitation>, DomainError> {
            Ok(self.by_user.lock().unwrap().values().find(|i| i.token_hash == token_hash).cloned())
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<hangar_domain::invitation::UserInvitation>, DomainError> {
            Ok(self.by_user.lock().unwrap().get(&user_id).cloned())
        }
        async fn list_pending_user_ids(&self, user_ids: &[Uuid]) -> Result<std::collections::HashSet<Uuid>, DomainError> {
            let by_user = self.by_user.lock().unwrap();
            Ok(user_ids.iter().filter(|id| by_user.contains_key(id)).copied().collect())
        }
        async fn delete(&self, user_id: Uuid) -> Result<(), DomainError> {
            self.by_user.lock().unwrap().remove(&user_id);
            Ok(())
        }
    }

    struct FakeOrganizations {
        by_id: Mutex<HashMap<Uuid, Organization>>,
    }

    impl FakeOrganizations {
        fn new() -> Self {
            Self { by_id: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl OrganizationRepositoryPort for FakeOrganizations {
        async fn create(&self, org: &Organization) -> Result<(), DomainError> {
            self.by_id.lock().unwrap().insert(org.id, org.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_slug(&self, slug: &OrganizationSlug) -> Result<Option<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().values().find(|o| &o.slug == slug).cloned())
        }
        async fn find_public(&self) -> Result<Organization, DomainError> {
            self.by_id.lock().unwrap().values().find(|o| o.is_public).cloned().ok_or_else(|| DomainError::Infrastructure("no public organization seeded".to_string()))
        }
        async fn list_all(&self) -> Result<Vec<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().values().cloned().collect())
        }
    }

    struct FakeHasher;

    #[async_trait]
    impl hangar_domain::user::PasswordHasherPort for FakeHasher {
        async fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
            Ok(format!("hashed:{plain_password}"))
        }
        async fn verify(&self, plain_password: &str, hash: &str) -> bool {
            hash == format!("hashed:{plain_password}")
        }
    }

    /// Fails to send only for addresses in `fail_for`.
    struct FakeEmail {
        sent: Mutex<Vec<(Uuid, String, String, String, String)>>,
        fail_for: std::collections::HashSet<String>,
    }

    impl FakeEmail {
        fn new() -> Self {
            Self { sent: Mutex::new(Vec::new()), fail_for: std::collections::HashSet::new() }
        }
        fn failing_for(addresses: &[&str]) -> Self {
            Self { sent: Mutex::new(Vec::new()), fail_for: addresses.iter().map(|s| s.to_string()).collect() }
        }
    }

    #[async_trait]
    impl hangar_domain::email::EmailPort for FakeEmail {
        async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
            if self.fail_for.contains(to) {
                return Err(DomainError::Infrastructure("simulated send failure".to_string()));
            }
            self.sent.lock().unwrap().push((organization_id, to.to_string(), subject.to_string(), text_body.to_string(), html_body.to_string()));
            Ok(())
        }
    }

    struct FakePermissionQuery {
        /// (repository_id, user_id, role)
        entries: Vec<(Uuid, Uuid, Role)>,
    }

    #[async_trait]
    impl PermissionQueryPort for FakePermissionQuery {
        async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError> {
            Ok(self.entries.iter().find(|(r, u, _)| *r == repository_id && *u == user_id).map(|(_, _, role)| *role))
        }
        async fn list_for_repository(&self, repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            Ok(self.entries.iter().filter(|(r, _, _)| *r == repository_id).map(|(_, u, role)| (*u, *role)).collect())
        }
        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            Ok(self.entries.iter().filter(|(_, u, _)| *u == user_id).map(|(r, _, role)| (*r, *role)).collect())
        }
        async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError> {
            Ok(self.entries.iter().map(|(r, u, role)| (*u, *r, *role)).collect())
        }
        async fn count_all(&self) -> Result<usize, EventStoreError> {
            Ok(self.entries.len())
        }
    }

    struct FakeMetricsSnapshots {
        saved: Mutex<Vec<MetricsSnapshot>>,
    }

    impl FakeMetricsSnapshots {
        fn new() -> Self {
            Self { saved: Mutex::new(Vec::new()) }
        }
    }

    #[async_trait]
    impl MetricsSnapshotRepositoryPort for FakeMetricsSnapshots {
        async fn save(&self, snapshot: &MetricsSnapshot) -> Result<(), DomainError> {
            self.saved.lock().unwrap().push(snapshot.clone());
            Ok(())
        }
        async fn list_since(&self, since: DateTime<Utc>) -> Result<Vec<MetricsSnapshot>, DomainError> {
            Ok(self.saved.lock().unwrap().iter().filter(|s| s.recorded_at >= since).cloned().collect())
        }
    }

    struct FakeEventPublisher {
        security_events: Mutex<Vec<SecurityEvent>>,
    }

    impl FakeEventPublisher {
        fn new() -> Self {
            Self { security_events: Mutex::new(Vec::new()) }
        }
    }

    #[async_trait]
    impl EventPublisherPort for FakeEventPublisher {
        async fn publish_security_event(&self, event: SecurityEvent, _actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
            self.security_events.lock().unwrap().push(event);
            Ok(())
        }

        async fn query_audit_log(&self, _filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, EventStoreError> {
            Ok(Vec::new())
        }

        async fn publish_npm_event(
            &self,
            _event: hangar_domain::audit::NpmPackageEvent,
            _npm_package_id: Uuid,
            _actor_id: Option<Uuid>,
        ) -> Result<(), EventStoreError> {
            Ok(())
        }

        async fn publish_docker_event(
            &self,
            _event: hangar_domain::audit::DockerRegistryEvent,
            _package_repository_id: Uuid,
            _actor_id: Option<Uuid>,
        ) -> Result<(), EventStoreError> {
            Ok(())
        }
    }

    struct FakeRepositoryQuery {
        repos: Vec<PackageRepositorySummary>,
    }

    #[async_trait]
    impl PackageRepositoryQueryPort for FakeRepositoryQuery {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            Ok(self.repos.iter().find(|r| r.id == id).cloned())
        }
        async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            Ok(self.repos.iter().find(|r| r.organization_id == organization_id && r.name == name).cloned())
        }
        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
            Ok(self.repos.clone())
        }
    }

    struct FakeDockerBlobs {
        used_bytes_by_repository: std::collections::HashMap<Uuid, u64>,
    }

    #[async_trait]
    impl DockerBlobStorePort for FakeDockerBlobs {
        async fn write(&self, _digest: &hangar_domain::docker_registry::Digest, _bytes: &[u8]) -> Result<(), DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn adopt_staged_file(&self, _digest: &hangar_domain::docker_registry::Digest, _staging_path: &str, _size_bytes: u64) -> Result<(), DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn read(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<Vec<u8>, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn read_stream(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<hangar_domain::docker_registry::ByteStream, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn link_to_repository(&self, _repository_id: Uuid, _digest: &hangar_domain::docker_registry::Digest) -> Result<(), DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn is_uploaded_to_repository(&self, _repository_id: Uuid, _digest: &hangar_domain::docker_registry::Digest) -> Result<bool, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn exists(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<bool, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn size_if_exists(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<Option<u64>, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn existing_digests(&self, _digests: &[hangar_domain::docker_registry::Digest]) -> Result<std::collections::HashSet<String>, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn sum_sizes(&self, _digests: &[hangar_domain::docker_registry::Digest]) -> Result<u64, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn increment_ref(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<(), DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn increment_ref_all(&self, _digests: &[hangar_domain::docker_registry::Digest]) -> Result<(), DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn decrement_ref_and_delete_if_zero(&self, _digest: &hangar_domain::docker_registry::Digest) -> Result<bool, DomainError> {
            unreachable!("not exercised by GetUsageMetricsUseCase's tests")
        }
        async fn used_bytes_for_repository(&self, repository_id: Uuid) -> Result<u64, DomainError> {
            Ok(self.used_bytes_by_repository.get(&repository_id).copied().unwrap_or(0))
        }
        async fn used_bytes_for_repositories(&self, repository_ids: &[Uuid]) -> Result<std::collections::HashMap<Uuid, u64>, DomainError> {
            Ok(repository_ids.iter().filter_map(|id| self.used_bytes_by_repository.get(id).map(|bytes| (*id, *bytes))).collect())
        }
    }

    struct FakeStorage {
        healthy: bool,
    }

    #[async_trait]
    impl StorageBackendPort for FakeStorage {
        async fn write(&self, _repository_id: Uuid, _path: &str, _data: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        async fn read(&self, _repository_id: Uuid, _path: &str) -> Result<Vec<u8>, StorageError> {
            Ok(Vec::new())
        }
        async fn read_stream(&self, _repository_id: Uuid, _path: &str) -> Result<hangar_domain::storage::ByteStream, StorageError> {
            Ok(Box::pin(futures::stream::once(async { Ok(bytes::Bytes::new()) })))
        }
        async fn delete(&self, _repository_id: Uuid, _path: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn used_bytes(&self, repository_id: Uuid) -> Result<u64, StorageError> {
            Ok(repository_id.as_u128() as u64 % 1000)
        }
        async fn is_healthy(&self) -> bool {
            self.healthy
        }
        async fn volume_space(&self) -> Result<hangar_domain::storage::VolumeSpace, StorageError> {
            Ok(hangar_domain::storage::VolumeSpace { total_bytes: 1000, free_bytes: 400 })
        }
    }

    struct FakeHealthCheck {
        healthy: bool,
    }

    #[async_trait]
    impl HealthCheckPort for FakeHealthCheck {
        async fn check(&self) -> DatabaseHealth {
            let status = if self.healthy { ComponentHealth::Up } else { ComponentHealth::Down("db down".to_string()) };
            DatabaseHealth {
                status,
                response_time_ms: 1,
                active_connections: 2,
                max_connections: 10,
                server_version: self.healthy.then(|| "16.0".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn records_and_queries_security_events() {
        let publisher = Arc::new(FakeEventPublisher::new());
        let record = RecordSecurityEventUseCase::new(publisher.clone());
        record
            .execute(
                SecurityEvent::LoginFailed { username: "florian".to_string(), ip: "127.0.0.1".to_string() },
                None,
            )
            .await
            .unwrap();
        assert_eq!(publisher.security_events.lock().unwrap().len(), 1);

        let query = QueryAuditLogUseCase::new(publisher);
        let entries = query.execute(AuditQueryFilter::default()).await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn computes_usage_metrics_for_an_npm_repository_from_the_storage_backend() {
        let repo_id = Uuid::new_v4();
        let repos = Arc::new(FakeRepositoryQuery {
            repos: vec![PackageRepositorySummary {
                id: repo_id,
                organization_id: Uuid::new_v4(),
                name: "my-repo".to_string(),
                format: RepositoryFormat::Npm,
                repo_type: RepositoryType::Hosted,
                remote_url: None,
                remote_username: None,
                remote_password: None,
                quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
            }],
        });
        let docker_blobs = Arc::new(FakeDockerBlobs { used_bytes_by_repository: std::collections::HashMap::new() });
        let use_case = GetUsageMetricsUseCase::new(repos, Arc::new(FakeStorage { healthy: true }), docker_blobs);
        let usages = use_case.execute().await.unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].repository_id, repo_id);
        assert_eq!(usages[0].used_bytes, repo_id.as_u128() as u64 % 1000);
    }

    #[tokio::test]
    async fn computes_usage_metrics_for_a_docker_repository_from_the_blob_store_not_the_storage_backend() {
        // Guards against silently falling back to storage.used_bytes() (always 0 for Docker).
        let repo_id = Uuid::new_v4();
        let repos = Arc::new(FakeRepositoryQuery {
            repos: vec![PackageRepositorySummary {
                id: repo_id,
                organization_id: Uuid::new_v4(),
                name: "my-image".to_string(),
                format: RepositoryFormat::Docker,
                repo_type: RepositoryType::Hosted,
                remote_url: None,
                remote_username: None,
                remote_password: None,
                quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
            }],
        });
        let docker_blobs =
            Arc::new(FakeDockerBlobs { used_bytes_by_repository: std::collections::HashMap::from([(repo_id, 4096u64)]) });
        let use_case = GetUsageMetricsUseCase::new(repos, Arc::new(FakeStorage { healthy: true }), docker_blobs);
        let usages = use_case.execute().await.unwrap();
        assert_eq!(usages.len(), 1);
        assert_eq!(usages[0].used_bytes, 4096);
    }

    #[tokio::test]
    async fn records_a_snapshot_of_current_totals() {
        let repo_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![
            User { id: Uuid::new_v4(), username: Username::parse("user-one").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: chrono::Utc::now(), tokens_valid_after: chrono::Utc::now(), email: None },
            User { id: Uuid::new_v4(), username: Username::parse("user-two").unwrap(), password_hash: "h".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: chrono::Utc::now(), tokens_valid_after: chrono::Utc::now(), email: None },
        ]));
        let repos = Arc::new(FakeRepositoryQuery {
            repos: vec![PackageRepositorySummary {
                id: repo_id,
                organization_id: Uuid::new_v4(),
                name: "my-repo".to_string(),
                format: RepositoryFormat::Docker,
                repo_type: RepositoryType::Hosted,
                remote_url: None,
                remote_username: None,
                remote_password: None,
                quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
            }],
        });
        let docker_blobs = Arc::new(FakeDockerBlobs { used_bytes_by_repository: std::collections::HashMap::from([(repo_id, 500u64)]) });
        let usage_metrics = Arc::new(GetUsageMetricsUseCase::new(repos, Arc::new(FakeStorage { healthy: true }), docker_blobs));
        let snapshots = Arc::new(FakeMetricsSnapshots::new());

        let use_case = RecordMetricsSnapshotUseCase::new(users, usage_metrics, snapshots.clone());
        use_case.execute().await.unwrap();

        let saved = snapshots.saved.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].total_users, 2);
        assert_eq!(saved[0].total_repositories, 1);
        assert_eq!(saved[0].total_storage_bytes, 500);
    }

    #[tokio::test]
    async fn get_metrics_history_returns_snapshots_since_the_given_time() {
        let snapshots = Arc::new(FakeMetricsSnapshots::new());
        let now = chrono::Utc::now();
        snapshots
            .save(&MetricsSnapshot { id: Uuid::new_v4(), recorded_at: now - chrono::Duration::days(40), total_users: 1, total_repositories: 1, total_storage_bytes: 1 })
            .await
            .unwrap();
        snapshots
            .save(&MetricsSnapshot { id: Uuid::new_v4(), recorded_at: now - chrono::Duration::days(1), total_users: 2, total_repositories: 2, total_storage_bytes: 2 })
            .await
            .unwrap();

        let use_case = GetMetricsHistoryUseCase::new(snapshots);
        let history = use_case.execute(now - chrono::Duration::days(30)).await.unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].total_users, 2);
    }

    #[tokio::test]
    async fn reports_health_of_dependencies() {
        let use_case = GetHealthStatusUseCase::new(
            Arc::new(FakeHealthCheck { healthy: true }),
            Arc::new(FakeStorage { healthy: false }),
            Instant::now(),
        );
        let status = use_case.execute().await;
        assert_eq!(status.database.status, ComponentHealth::Up);
        assert_eq!(status.database.server_version, Some("16.0".to_string()));
        assert_eq!(status.storage.status, ComponentHealth::Down("storage backend unreachable".to_string()));
        assert_eq!(status.storage.total_bytes, 1000);
        assert_eq!(status.storage.free_bytes, 400);
        assert_eq!(status.storage.used_bytes, 600);
    }

    #[tokio::test]
    async fn reports_uptime_elapsed_since_the_use_case_was_built() {
        let started_at = Instant::now() - std::time::Duration::from_secs(120);
        let use_case = GetHealthStatusUseCase::new(Arc::new(FakeHealthCheck { healthy: true }), Arc::new(FakeStorage { healthy: true }), started_at);

        let status = use_case.execute().await;

        assert!(status.uptime_seconds >= 120, "got {}", status.uptime_seconds);
    }

    #[tokio::test]
    async fn computes_totals_across_users_repositories_and_permissions() {
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![
            User { id: user_id, username: Username::parse("florian").unwrap(), password_hash: "hash".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: chrono::Utc::now(), tokens_valid_after: chrono::Utc::now(), email: None },
            User { id: other_user_id, username: Username::parse("regular").unwrap(), password_hash: "hash".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: chrono::Utc::now(), tokens_valid_after: chrono::Utc::now(), email: None },
        ]));
        let repos = Arc::new(FakeRepositoryQuery {
            repos: vec![
                PackageRepositorySummary { id: repo_a, organization_id: Uuid::new_v4(), name: "repo-a".to_string(), format: RepositoryFormat::Npm, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] },
                PackageRepositorySummary { id: repo_b, organization_id: Uuid::new_v4(), name: "repo-b".to_string(), format: RepositoryFormat::Npm, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] },
            ],
        });
        let permissions = Arc::new(FakePermissionQuery {
            entries: vec![(repo_a, user_id, Role::Write), (repo_a, other_user_id, Role::Read), (repo_b, user_id, Role::Admin)],
        });

        let use_case = GetAdminStatsUseCase::new(users, repos, permissions);
        let stats = use_case.execute().await.unwrap();

        assert_eq!(stats.total_users, 2);
        assert_eq!(stats.total_repositories, 2);
        assert_eq!(stats.total_active_permissions, 3);
    }

    #[tokio::test]
    async fn reports_zero_totals_on_a_fresh_instance() {
        let use_case = GetAdminStatsUseCase::new(
            Arc::new(FakeUsers::seeded(vec![])),
            Arc::new(FakeRepositoryQuery { repos: vec![] }),
            Arc::new(FakePermissionQuery { entries: vec![] }),
        );
        let stats = use_case.execute().await.unwrap();
        assert_eq!(stats.total_users, 0);
        assert_eq!(stats.total_repositories, 0);
        assert_eq!(stats.total_active_permissions, 0);
    }

    struct FakeApiTokens {
        tokens: Mutex<Vec<hangar_domain::api_token::ApiToken>>,
    }

    #[async_trait]
    impl hangar_domain::api_token::ApiTokenRepositoryPort for FakeApiTokens {
        async fn insert(&self, token: &hangar_domain::api_token::ApiToken) -> Result<(), DomainError> {
            self.tokens.lock().unwrap().push(token.clone());
            Ok(())
        }
        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<hangar_domain::api_token::ApiToken>, DomainError> {
            Ok(self.tokens.lock().unwrap().iter().filter(|t| t.user_id == user_id).cloned().collect())
        }
        async fn list_all(&self) -> Result<Vec<hangar_domain::api_token::ApiToken>, DomainError> {
            Ok(self.tokens.lock().unwrap().clone())
        }
        async fn find_by_hash(&self, token_hash: &str) -> Result<Option<hangar_domain::api_token::ApiToken>, DomainError> {
            Ok(self.tokens.lock().unwrap().iter().find(|t| t.token_hash == token_hash).cloned())
        }
        async fn touch_last_used_at(&self, _id: Uuid, _used_at: DateTime<Utc>) -> Result<(), DomainError> {
            Ok(())
        }
        async fn revoke(&self, id: Uuid, user_id: Uuid) -> Result<bool, DomainError> {
            if let Some(t) = self.tokens.lock().unwrap().iter_mut().find(|t| t.id == id && t.user_id == user_id) {
                t.revoked_at = Some(Utc::now());
                return Ok(true);
            }
            Ok(false)
        }
        async fn revoke_any(&self, id: Uuid) -> Result<(), DomainError> {
            if let Some(t) = self.tokens.lock().unwrap().iter_mut().find(|t| t.id == id) {
                t.revoked_at = Some(Utc::now());
            }
            Ok(())
        }
    }

    fn sample_token(user_id: Uuid, label: &str) -> hangar_domain::api_token::ApiToken {
        hangar_domain::api_token::ApiToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: format!("hash-{label}"),
            label: label.to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn lists_tokens_across_every_user_with_their_username() {
        let alice_id = Uuid::new_v4();
        let bob_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![
            User { id: alice_id, username: Username::parse("alice").unwrap(), password_hash: "h".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None },
            User { id: bob_id, username: Username::parse("bob").unwrap(), password_hash: "h".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None },
        ]));
        let tokens = Arc::new(FakeApiTokens { tokens: Mutex::new(vec![sample_token(alice_id, "laptop"), sample_token(bob_id, "ci")]) });

        let use_case = AdminListApiTokensUseCase::new(tokens, users);
        let mut entries = use_case.execute().await.unwrap();
        entries.sort_by(|a, b| a.label.cmp(&b.label));

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].username, "bob");
        assert_eq!(entries[0].label, "ci");
        assert_eq!(entries[1].username, "alice");
        assert_eq!(entries[1].label, "laptop");
    }

    #[tokio::test]
    async fn a_token_whose_owner_no_longer_exists_is_still_listed_with_a_placeholder_username() {
        let orphaned_user_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![]));
        let tokens = Arc::new(FakeApiTokens { tokens: Mutex::new(vec![sample_token(orphaned_user_id, "leftover")]) });

        let use_case = AdminListApiTokensUseCase::new(tokens, users);
        let entries = use_case.execute().await.unwrap();

        assert_eq!(entries.len(), 1, "an orphaned token must stay visible to oversight, not disappear");
        assert_eq!(entries[0].label, "leftover");
        assert_eq!(entries[0].user_id, orphaned_user_id);
        assert_eq!(entries[0].username, "(utilisateur supprimé)");
    }

    #[tokio::test]
    async fn admin_revoke_revokes_a_token_owned_by_a_different_user() {
        let owner_id = Uuid::new_v4();
        let token = sample_token(owner_id, "laptop");
        let token_id = token.id;
        let tokens = Arc::new(FakeApiTokens { tokens: Mutex::new(vec![token]) });

        let revoke = AdminRevokeApiTokenUseCase::new(tokens.clone());
        revoke.execute(token_id).await.unwrap();

        let stored = tokens.list_all().await.unwrap();
        assert!(stored[0].revoked_at.is_some(), "admin revoke must succeed regardless of who owns the token");
    }

    struct FakeSystemSettings {
        settings: Mutex<std::collections::HashMap<Uuid, SystemSettings>>,
    }

    #[async_trait]
    impl SystemSettingsPort for FakeSystemSettings {
        async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError> {
            Ok(self.settings.lock().unwrap().get(&organization_id).copied().unwrap_or(SystemSettings::defaults()))
        }
        async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError> {
            self.settings.lock().unwrap().insert(organization_id, *settings);
            Ok(())
        }
    }

    #[tokio::test]
    async fn get_system_settings_returns_the_current_values() {
        let org_id = Uuid::new_v4();
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = GetSystemSettingsUseCase::new(settings);
        assert_eq!(use_case.execute(org_id).await.unwrap(), SystemSettings::defaults());
    }

    #[tokio::test]
    async fn update_system_settings_persists_valid_values() {
        let org_id = Uuid::new_v4();
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = UpdateSystemSettingsUseCase::new(settings.clone());
        let updated = SystemSettings { max_login_attempts: 5, login_attempt_window_seconds: 60, session_ttl_hours: 1, registration_enabled: false };

        use_case.execute(org_id, updated).await.unwrap();

        assert_eq!(settings.get(org_id).await.unwrap(), updated);
    }

    #[tokio::test]
    async fn update_system_settings_rejects_a_zero_login_attempt_limit() {
        let org_id = Uuid::new_v4();
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = UpdateSystemSettingsUseCase::new(settings.clone());

        let err = use_case.execute(org_id, SystemSettings { max_login_attempts: 0, ..SystemSettings::defaults() }).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidSystemSettings(_)));
        assert_eq!(settings.get(org_id).await.unwrap(), SystemSettings::defaults(), "an invalid update must not be persisted");
    }

    #[tokio::test]
    async fn update_system_settings_rejects_an_excessive_session_ttl() {
        let org_id = Uuid::new_v4();
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = UpdateSystemSettingsUseCase::new(settings);

        let err = use_case.execute(org_id, SystemSettings { session_ttl_hours: 10_000, ..SystemSettings::defaults() }).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidSystemSettings(_)));
    }

    #[tokio::test]
    async fn exports_users_repositories_permissions_and_settings() {
        let admin_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![
            User { id: admin_id, username: Username::parse("admin").unwrap(), password_hash: "secret-hash".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: Some("admin@example.com".to_string()) },
            User { id: member_id, username: Username::parse("member").unwrap(), password_hash: "secret-hash".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None },
        ]));
        let repositories = Arc::new(FakeRepositoryQuery {
            repos: vec![PackageRepositorySummary {
                id: repo_id,
                organization_id: Uuid::new_v4(),
                name: "my-repo".to_string(),
                format: RepositoryFormat::Npm,
                repo_type: RepositoryType::Proxy,
                remote_url: Some("https://registry.npmjs.org".to_string()),
                remote_username: Some("svc-account".to_string()),
                remote_password: Some("s3cret-upstream-token".to_string()),
                group_members: vec![],
                quota_bytes: Some(1024),
                retention_keep_last_n: Some(5),
            }],
        });
        let permissions = Arc::new(FakePermissionQuery { entries: vec![(repo_id, member_id, Role::Write)] });
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });

        let use_case = ExportConfigurationUseCase::new(users, repositories, permissions, settings);
        let export = use_case.execute().await.unwrap();

        assert_eq!(export.users.len(), 2);
        assert!(export.users.iter().any(|u| u.username == "admin" && u.is_super_admin));
        assert_eq!(export.repositories.len(), 1);
        assert_eq!(export.repositories[0].quota_bytes, Some(1024));
        assert_eq!(export.repositories[0].retention_keep_last_n, Some(5));
        assert_eq!(export.repositories[0].remote_username, None, "credentials must never leave via the downloadable export");
        assert_eq!(export.repositories[0].remote_password, None, "credentials must never leave via the downloadable export");
        assert_eq!(export.permissions.len(), 1);
        assert_eq!(export.permissions[0].user_id, member_id);
        assert_eq!(export.permissions[0].role, Role::Write);
        assert_eq!(export.system_settings, SystemSettings::defaults());
        assert_eq!(export.users.iter().find(|u| u.username == "admin").unwrap().email, Some("admin@example.com".to_string()));
    }

    const TEST_BASE_DOMAIN: &str = "hangar.example.com";

    /// One public org per distinct organization_id already on `users` — tests needing a non-public restore org build their own `FakeOrganizations` instead.
    fn public_orgs_for(users: &FakeUsers) -> Arc<FakeOrganizations> {
        let organizations = Arc::new(FakeOrganizations::new());
        for organization_id in users.users.lock().unwrap().values().map(|u| u.organization_id).collect::<std::collections::HashSet<_>>() {
            organizations.by_id.lock().unwrap().insert(organization_id, Organization { id: organization_id, slug: OrganizationSlug::parse("public").unwrap(), display_name: "Public".to_string(), is_public: true, created_at: Utc::now() });
        }
        organizations
    }

    fn import_use_case(
        users: Arc<FakeUsers>,
        repos: Arc<FakePackageRepositoryStore>,
        permissions: Arc<FakePermissionStore>,
        settings: Arc<FakeSystemSettings>,
        invitations: Arc<FakeInvitations>,
        email: Arc<FakeEmail>,
    ) -> ImportConfigurationUseCase {
        let organizations = public_orgs_for(&users);
        ImportConfigurationUseCase::new(
            users.clone(),
            Arc::new(FakeHasher),
            Arc::new(CreatePackageRepositoryUseCase::new(repos.clone(), repos.clone())),
            Arc::new(SetRepositoryQuotaUseCase::new(repos.clone())),
            Arc::new(SetRetentionPolicyUseCase::new(repos.clone())),
            Arc::new(AddGroupMemberUseCase::new(repos.clone(), repos.clone())),
            Arc::new(GrantPermissionUseCase::new(permissions.clone(), repos.clone(), users.clone())),
            Arc::new(UpdateSystemSettingsUseCase::new(settings.clone())),
            repos.clone(),
            invitations,
            email,
            organizations,
            TEST_BASE_DOMAIN.to_string(),
        )
    }

    fn sample_import() -> ConfigurationImport {
        let admin_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let hosted_id = Uuid::new_v4();
        ConfigurationImport {
            users: vec![
                ExportedUser { id: admin_id, username: "admin".to_string(), is_super_admin: true, created_at: Utc::now(), email: Some("admin@example.com".to_string()) },
                ExportedUser { id: member_id, username: "member".to_string(), is_super_admin: false, created_at: Utc::now(), email: None },
            ],
            repositories: vec![
                // Group listed before its member: proves forward references are handled.
                ExportedRepository { id: group_id, name: "my-group".to_string(), format: RepositoryFormat::Npm, repo_type: RepositoryType::Group, remote_url: None, remote_username: None, remote_password: None, group_members: vec![hosted_id], quota_bytes: None, retention_keep_last_n: None },
                ExportedRepository { id: hosted_id, name: "my-hosted".to_string(), format: RepositoryFormat::Npm, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, group_members: vec![], quota_bytes: Some(1024), retention_keep_last_n: Some(5) },
            ],
            permissions: vec![ExportedPermission { user_id: member_id, repository_id: hosted_id, role: Role::Write }],
            system_settings: SystemSettings { max_login_attempts: 7, ..SystemSettings::defaults() },
        }
    }

    #[tokio::test]
    async fn rejects_import_when_a_repository_already_exists() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        Arc::new(CreatePackageRepositoryUseCase::new(repos.clone(), repos.clone())).execute(Uuid::new_v4(), "existing", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, caller_id).await.unwrap();
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = import_use_case(users, repos, permissions, settings, Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));

        let err = use_case.execute(sample_import(), caller_id).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InstanceNotEmpty));
    }

    #[tokio::test]
    async fn rejects_import_when_another_user_already_exists() {
        let caller_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![
            User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None },
            User { id: other_id, username: Username::parse("other").unwrap(), password_hash: "h".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None },
        ]));
        let use_case = import_use_case(users, Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));

        let err = use_case.execute(sample_import(), caller_id).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InstanceNotEmpty));
    }

    #[tokio::test]
    async fn rejects_import_with_a_clear_error_when_the_acting_admins_own_user_row_is_gone() {
        // The instance-empty guards above only check OTHER users — a caller whose own row is gone sails right past them.
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![]));
        let use_case = import_use_case(users, Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));

        let err = use_case.execute(sample_import(), caller_id).await.unwrap_err();

        assert!(matches!(err, ApplicationError::ActingAdminNotFound));
    }

    #[tokio::test]
    async fn restores_users_repositories_permissions_and_settings_on_an_empty_instance() {
        let caller_id = Uuid::new_v4();
        let caller_org_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: caller_org_id, created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let invitations = Arc::new(FakeInvitations::new());
        let email = Arc::new(FakeEmail::new());
        let use_case = import_use_case(users.clone(), repos.clone(), permissions.clone(), settings.clone(), invitations.clone(), email.clone());
        let import = sample_import();

        let report = use_case.execute(import.clone(), caller_id).await.unwrap();

        assert_eq!(report.users_created, 2);
        assert_eq!(report.repositories_created, 2);
        assert_eq!(report.permissions_granted, 1);
        assert_eq!(report.invited, vec!["admin".to_string()]);
        assert_eq!(report.skipped_no_email, vec!["member".to_string()]);
        assert!(report.failed.is_empty());

        let restored = repos.list_all().await.unwrap();
        assert_eq!(restored.len(), 2);
        assert!(restored.iter().all(|r| r.id != import.repositories[0].id && r.id != import.repositories[1].id));

        let restored_hosted = restored.iter().find(|r| r.name == "my-hosted").unwrap();
        assert_eq!(restored_hosted.quota_bytes, Some(1024));
        assert_eq!(restored_hosted.retention_keep_last_n, Some(5));
        let restored_group = restored.iter().find(|r| r.name == "my-group").unwrap();
        assert_eq!(restored_group.group_members, vec![restored_hosted.id]);

        let restored_member = users.find_by_id(import.users[1].id).await.unwrap().unwrap();
        assert_eq!(restored_member.username.as_str(), "member");

        let (version, _) = permissions.load(import.users[1].id, restored_hosted.id).await.unwrap();
        assert_eq!(version, 1);
        assert_eq!(settings.settings.lock().unwrap().get(&caller_org_id).unwrap().max_login_attempts, 7);

        let sent = email.sent.lock().unwrap();
        assert!(sent[0].3.contains(&format!("https://{TEST_BASE_DOMAIN}/activate?token=")), "expected the public organization's own origin, got: {}", sent[0].3);
    }

    #[tokio::test]
    async fn a_restore_into_a_non_public_organization_links_to_that_organizations_own_subdomain() {
        let caller_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id, created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let invitations = Arc::new(FakeInvitations::new());
        let email = Arc::new(FakeEmail::new());
        let organizations = Arc::new(FakeOrganizations::new());
        organizations.create(&Organization { id: organization_id, slug: OrganizationSlug::parse("acme").unwrap(), display_name: "Acme".to_string(), is_public: false, created_at: Utc::now() }).await.unwrap();
        let use_case = ImportConfigurationUseCase::new(
            users.clone(),
            Arc::new(FakeHasher),
            Arc::new(CreatePackageRepositoryUseCase::new(repos.clone(), repos.clone())),
            Arc::new(SetRepositoryQuotaUseCase::new(repos.clone())),
            Arc::new(SetRetentionPolicyUseCase::new(repos.clone())),
            Arc::new(AddGroupMemberUseCase::new(repos.clone(), repos.clone())),
            Arc::new(GrantPermissionUseCase::new(permissions, repos.clone(), users)),
            Arc::new(UpdateSystemSettingsUseCase::new(settings)),
            repos,
            invitations,
            email.clone(),
            organizations,
            TEST_BASE_DOMAIN.to_string(),
        );

        let report = use_case.execute(sample_import(), caller_id).await.unwrap();

        assert_eq!(report.invited, vec!["admin".to_string()], "got failures: {:?}", report.failed);
        let sent = email.sent.lock().unwrap();
        assert!(sent[0].3.contains("https://acme.hangar.example.com/activate?token="), "expected the acme subdomain, got: {}", sent[0].3);
    }

    #[tokio::test]
    async fn restored_users_join_the_acting_admins_own_organization() {
        let caller_id = Uuid::new_v4();
        let caller_org_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User {
            id: caller_id,
            username: Username::parse("caller").unwrap(),
            password_hash: "h".to_string(),
            is_super_admin: true,
            is_organization_admin: false,
            organization_id: caller_org_id,
            created_at: Utc::now(),
            tokens_valid_after: Utc::now(),
            email: None,
        }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let invitations = Arc::new(FakeInvitations::new());
        let email = Arc::new(FakeEmail::new());
        let use_case = import_use_case(users.clone(), repos, permissions, settings, invitations, email);
        let import = sample_import();

        let report = use_case.execute(import.clone(), caller_id).await.unwrap();
        assert_eq!(report.users_created, 2, "got failures: {:?}", report.failed);

        let restored_admin = users.find_by_id(import.users[0].id).await.unwrap().unwrap();
        let restored_member = users.find_by_id(import.users[1].id).await.unwrap().unwrap();
        assert_eq!(restored_admin.organization_id, caller_org_id, "restored users must join the acting admin's own organization");
        assert_eq!(restored_member.organization_id, caller_org_id, "restored users must join the acting admin's own organization");
    }

    #[tokio::test]
    async fn restoring_a_proxy_repository_also_restores_its_remote_credentials() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = import_use_case(users, repos.clone(), permissions, settings, Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));
        let import = ConfigurationImport {
            users: vec![],
            repositories: vec![ExportedRepository {
                id: Uuid::new_v4(),
                name: "proxy-repo".to_string(),
                format: RepositoryFormat::Npm,
                repo_type: RepositoryType::Proxy,
                remote_url: Some("https://registry.npmjs.org".to_string()),
                remote_username: Some("svc-account".to_string()),
                remote_password: Some("s3cret-upstream-token".to_string()),
                group_members: vec![],
                quota_bytes: None,
                retention_keep_last_n: None,
            }],
            permissions: vec![],
            system_settings: SystemSettings::defaults(),
        };

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert_eq!(report.repositories_created, 1, "got failures: {:?}", report.failed);
        let restored = repos.list_all().await.unwrap();
        assert_eq!(restored[0].remote_username.as_deref(), Some("svc-account"));
        assert_eq!(restored[0].remote_password.as_deref(), Some("s3cret-upstream-token"));
        assert!(report.proxy_credentials_needed.is_empty(), "credentials were supplied, nothing to flag");
    }

    #[tokio::test]
    async fn restoring_a_proxy_repository_with_no_credentials_flags_it_in_the_report() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let repos = Arc::new(FakePackageRepositoryStore::new());
        let permissions = Arc::new(FakePermissionStore::new());
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = import_use_case(users, repos.clone(), permissions, settings, Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));
        // The normal shape of an export: no credentials, since they're never included in it.
        let import = ConfigurationImport {
            users: vec![],
            repositories: vec![ExportedRepository {
                id: Uuid::new_v4(),
                name: "proxy-repo".to_string(),
                format: RepositoryFormat::Npm,
                repo_type: RepositoryType::Proxy,
                remote_url: Some("https://registry.npmjs.org".to_string()),
                remote_username: None,
                remote_password: None,
                group_members: vec![],
                quota_bytes: None,
                retention_keep_last_n: None,
            }],
            permissions: vec![],
            system_settings: SystemSettings::defaults(),
        };

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert_eq!(report.repositories_created, 1, "got failures: {:?}", report.failed);
        assert_eq!(report.proxy_credentials_needed, vec!["proxy-repo".to_string()]);
    }

    #[tokio::test]
    async fn a_restored_user_without_an_email_is_not_invited() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let invitations = Arc::new(FakeInvitations::new());
        let use_case = import_use_case(users, Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), invitations.clone(), Arc::new(FakeEmail::new()));
        let import = sample_import();
        let member_id = import.users[1].id;

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert!(report.invited.iter().all(|u| u != "member"));
        assert!(report.skipped_no_email.contains(&"member".to_string()));
        assert!(invitations.find_by_user_id(member_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_username_collision_with_the_calling_admin_is_reported_not_a_raw_db_error() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("admin").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let use_case = import_use_case(users.clone(), Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));
        let import = sample_import();
        let member_id = import.users[1].id;

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert_eq!(report.users_created, 1, "only member should have been created — admin collides with the caller");
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].contains("admin"), "got: {:?}", report.failed[0]);
        assert!(!report.failed[0].to_lowercase().contains("duplicate key"), "must not leak the raw Postgres error: {:?}", report.failed[0]);

        assert!(!report.invited.contains(&"admin".to_string()));
        assert!(!report.skipped_no_email.contains(&"admin".to_string()));
        assert!(users.find_by_id(member_id).await.unwrap().is_some());
        assert_eq!(report.repositories_created, 2);
        assert_eq!(report.permissions_granted, 1);
    }

    #[tokio::test]
    async fn a_user_whose_insert_fails_does_not_get_permissions_or_an_invitation_entry() {
        // A permission referencing the colliding user's id must fail, not silently target an orphaned user_id.
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("admin").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let mut import = sample_import();
        let admin_export_id = import.users[0].id;
        let hosted_id = import.repositories[1].id;
        import.permissions.push(ExportedPermission { user_id: admin_export_id, repository_id: hosted_id, role: Role::Read });
        let use_case = import_use_case(users, Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert_eq!(report.permissions_granted, 1);
        assert!(report.failed.iter().any(|f| f.contains(&admin_export_id.to_string())), "expected a failure entry for the orphaned permission, got: {:?}", report.failed);
    }

    #[tokio::test]
    async fn a_duplicate_repository_name_in_the_export_fails_that_one_repository_but_the_rest_of_the_import_continues() {
        let caller_id = Uuid::new_v4();
        let caller_org_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: caller_org_id, created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let mut import = sample_import();
        let duplicate_name = import.repositories[0].name.clone();
        import.repositories[1].name = duplicate_name.clone();
        let settings = Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) });
        let use_case = import_use_case(users.clone(), Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), settings.clone(), Arc::new(FakeInvitations::new()), Arc::new(FakeEmail::new()));
        let member_id = import.users[1].id;

        let report = use_case.execute(import, caller_id).await.unwrap();

        assert_eq!(report.repositories_created, 1);
        assert!(
            report.failed.iter().any(|f| f.contains(&duplicate_name) && f.contains("already taken")),
            "expected a repository-name-taken failure for {duplicate_name:?}, got: {:?}",
            report.failed
        );

        assert_eq!(report.users_created, 2);
        assert!(users.find_by_id(member_id).await.unwrap().is_some());
        assert_eq!(settings.get(caller_org_id).await.unwrap().max_login_attempts, 7);
    }

    #[tokio::test]
    async fn a_failed_invitation_email_is_reported_but_does_not_fail_the_import() {
        let caller_id = Uuid::new_v4();
        let users = Arc::new(FakeUsers::seeded(vec![User { id: caller_id, username: Username::parse("caller").unwrap(), password_hash: "h".to_string(), is_super_admin: true, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }]));
        let email = Arc::new(FakeEmail::failing_for(&["admin@example.com"]));
        let use_case = import_use_case(users, Arc::new(FakePackageRepositoryStore::new()), Arc::new(FakePermissionStore::new()), Arc::new(FakeSystemSettings { settings: Mutex::new(HashMap::new()) }), Arc::new(FakeInvitations::new()), email);

        let report = use_case.execute(sample_import(), caller_id).await.unwrap();

        assert!(report.invited.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].contains("admin"));
        assert_eq!(report.users_created, 2);
    }
}
