use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{DomainError, EventStoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryFormat {
    Npm,
    Docker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryType {
    Hosted,
    Proxy,
    Group,
}

pub fn parse_repository_name(raw: &str) -> Result<String, DomainError> {
    let len_ok = (2..=64).contains(&raw.len());
    let chars_ok = raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if len_ok && chars_ok {
        Ok(raw.to_string())
    } else {
        Err(DomainError::InvalidRepositoryName(raw.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum PackageRepositoryEvent {
    Created {
        repository_id: Uuid,
        organization_id: Uuid,
        name: String,
        format: RepositoryFormat,
        repo_type: RepositoryType,
        remote_url: Option<String>,
        remote_username: Option<String>,
        /// Basic-auth password, or a bearer token when `remote_username` is `None`. Never returned by the API.
        remote_password: Option<String>,
    },
    Renamed { repository_id: Uuid, new_name: String },
    RemoteUrlChanged { repository_id: Uuid, remote_url: String },
    GroupMemberAdded { repository_id: Uuid, member_repository_id: Uuid, position: i32 },
    GroupMemberRemoved { repository_id: Uuid, member_repository_id: Uuid },
    /// `None` means unlimited.
    QuotaSet { repository_id: Uuid, quota_bytes: Option<i64> },
    /// `None` disables the background retention sweep for this repository.
    RetentionPolicySet { repository_id: Uuid, keep_last_n_versions: Option<i32> },
    Deleted { repository_id: Uuid },
}

impl PackageRepositoryEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            PackageRepositoryEvent::Created { .. } => "Created",
            PackageRepositoryEvent::Renamed { .. } => "Renamed",
            PackageRepositoryEvent::RemoteUrlChanged { .. } => "RemoteUrlChanged",
            PackageRepositoryEvent::GroupMemberAdded { .. } => "GroupMemberAdded",
            PackageRepositoryEvent::GroupMemberRemoved { .. } => "GroupMemberRemoved",
            PackageRepositoryEvent::QuotaSet { .. } => "QuotaSet",
            PackageRepositoryEvent::RetentionPolicySet { .. } => "RetentionPolicySet",
            PackageRepositoryEvent::Deleted { .. } => "Deleted",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PackageRepository {
    pub name: Option<String>,
    pub format: Option<RepositoryFormat>,
    pub repo_type: Option<RepositoryType>,
    pub remote_url: Option<String>,
    pub remote_username: Option<String>,
    pub remote_password: Option<String>,
    pub group_members: Vec<(Uuid, i32)>,
    pub quota_bytes: Option<i64>,
    pub retention_keep_last_n: Option<i32>,
    pub deleted: bool,
}

impl PackageRepository {
    pub fn from_events(events: &[PackageRepositoryEvent]) -> Self {
        let mut state = Self::default();
        for event in events {
            state.apply(event);
        }
        state
    }

    pub fn apply(&mut self, event: &PackageRepositoryEvent) {
        match event {
            PackageRepositoryEvent::Created { name, format, repo_type, remote_url, remote_username, remote_password, .. } => {
                self.name = Some(name.clone());
                self.format = Some(*format);
                self.repo_type = Some(*repo_type);
                self.remote_url = remote_url.clone();
                self.remote_username = remote_username.clone();
                self.remote_password = remote_password.clone();
            }
            PackageRepositoryEvent::Renamed { new_name, .. } => self.name = Some(new_name.clone()),
            PackageRepositoryEvent::RemoteUrlChanged { remote_url, .. } => {
                self.remote_url = Some(remote_url.clone())
            }
            PackageRepositoryEvent::GroupMemberAdded { member_repository_id, position, .. } => {
                self.group_members.retain(|(id, _)| id != member_repository_id);
                self.group_members.push((*member_repository_id, *position));
            }
            PackageRepositoryEvent::GroupMemberRemoved { member_repository_id, .. } => {
                self.group_members.retain(|(id, _)| id != member_repository_id);
            }
            PackageRepositoryEvent::QuotaSet { quota_bytes, .. } => self.quota_bytes = *quota_bytes,
            PackageRepositoryEvent::RetentionPolicySet { keep_last_n_versions, .. } => self.retention_keep_last_n = *keep_last_n_versions,
            PackageRepositoryEvent::Deleted { .. } => self.deleted = true,
        }
    }

    fn ensure_mutable(&self) -> Result<(), DomainError> {
        if self.deleted {
            Err(DomainError::AlreadyDeleted)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create(
        repository_id: Uuid,
        organization_id: Uuid,
        name: String,
        format: RepositoryFormat,
        repo_type: RepositoryType,
        remote_url: Option<String>,
        remote_username: Option<String>,
        remote_password: Option<String>,
    ) -> PackageRepositoryEvent {
        PackageRepositoryEvent::Created { repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password }
    }

    /// `repository_id` is `Uuid::nil()` here (and in every mutator below) — this aggregate doesn't track its own id; the application layer fills in the real one before persisting.
    pub fn rename(&self, new_name: String) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        Ok(PackageRepositoryEvent::Renamed { repository_id: Uuid::nil(), new_name })
    }

    pub fn change_remote_url(&self, remote_url: String) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        if self.repo_type != Some(RepositoryType::Proxy) {
            return Err(DomainError::InvalidForRepositoryType(
                "remote_url can only be set on a proxy repository".to_string(),
            ));
        }
        Ok(PackageRepositoryEvent::RemoteUrlChanged { repository_id: Uuid::nil(), remote_url })
    }

    pub fn add_group_member(&self, member_repository_id: Uuid, position: i32) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        if self.repo_type != Some(RepositoryType::Group) {
            return Err(DomainError::InvalidForRepositoryType(
                "group members can only be added to a group repository".to_string(),
            ));
        }
        Ok(PackageRepositoryEvent::GroupMemberAdded {
            repository_id: Uuid::nil(),
            member_repository_id,
            position,
        })
    }

    pub fn remove_group_member(&self, member_repository_id: Uuid) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        Ok(PackageRepositoryEvent::GroupMemberRemoved { repository_id: Uuid::nil(), member_repository_id })
    }

    pub fn delete(&self) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        Ok(PackageRepositoryEvent::Deleted { repository_id: Uuid::nil() })
    }

    pub fn set_quota(&self, quota_bytes: Option<i64>) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        if let Some(bytes) = quota_bytes {
            if bytes < 0 {
                return Err(DomainError::Validation("quota_bytes must not be negative".to_string()));
            }
        }
        Ok(PackageRepositoryEvent::QuotaSet { repository_id: Uuid::nil(), quota_bytes })
    }

    /// Keeps the `n` most recent versions/tags; the sweep deletes the rest.
    pub fn set_retention_policy(&self, keep_last_n_versions: Option<i32>) -> Result<PackageRepositoryEvent, DomainError> {
        self.ensure_mutable()?;
        if let Some(n) = keep_last_n_versions {
            if n < 1 {
                return Err(DomainError::Validation("keep_last_n_versions must be at least 1".to_string()));
            }
        }
        Ok(PackageRepositoryEvent::RetentionPolicySet { repository_id: Uuid::nil(), keep_last_n_versions })
    }
}

#[derive(Debug, Clone)]
pub struct PackageRepositorySummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub remote_url: Option<String>,
    pub remote_username: Option<String>,
    /// Never returned by the API.
    pub remote_password: Option<String>,
    pub group_members: Vec<Uuid>,
    /// `None` means unlimited.
    pub quota_bytes: Option<i64>,
    /// `None` means automatic cleanup is disabled for this repository.
    pub retention_keep_last_n: Option<i32>,
}

#[async_trait]
pub trait PackageRepositoryEventStorePort: Send + Sync {
    async fn load(&self, repository_id: Uuid) -> Result<(u64, Vec<PackageRepositoryEvent>), EventStoreError>;

    async fn append(
        &self,
        repository_id: Uuid,
        expected_version: u64,
        events: Vec<PackageRepositoryEvent>,
        actor_id: Uuid,
    ) -> Result<(), EventStoreError>;
}

#[async_trait]
pub trait PackageRepositoryQueryPort: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError>;
    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError>;
    async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn created_event(repository_id: Uuid, repo_type: RepositoryType) -> PackageRepositoryEvent {
        PackageRepositoryEvent::Created {
            repository_id,
            organization_id: Uuid::new_v4(),
            name: "my-repo".to_string(),
            format: RepositoryFormat::Npm,
            repo_type,
            remote_url: None,
            remote_username: None,
            remote_password: None,
        }
    }

    #[test]
    fn creating_sets_the_initial_state() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted)]);
        assert_eq!(repo.name.as_deref(), Some("my-repo"));
        assert_eq!(repo.repo_type, Some(RepositoryType::Hosted));
        assert!(!repo.deleted);
    }

    #[test]
    fn renaming_updates_the_name() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted)]);
        let event = repo.rename("renamed-repo".to_string()).unwrap();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted), event]);
        assert_eq!(repo.name.as_deref(), Some("renamed-repo"));
    }

    #[test]
    fn changing_remote_url_requires_proxy_type() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted)]);
        let err = repo.change_remote_url("https://registry.npmjs.org".to_string()).unwrap_err();
        assert!(matches!(err, DomainError::InvalidForRepositoryType(_)));
    }

    #[test]
    fn changing_remote_url_on_a_proxy_succeeds() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Proxy)]);
        let event = repo.change_remote_url("https://registry.npmjs.org".to_string()).unwrap();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Proxy), event]);
        assert_eq!(repo.remote_url.as_deref(), Some("https://registry.npmjs.org"));
    }

    #[test]
    fn adding_a_group_member_requires_group_type() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted)]);
        let err = repo.add_group_member(Uuid::new_v4(), 0).unwrap_err();
        assert!(matches!(err, DomainError::InvalidForRepositoryType(_)));
    }

    #[test]
    fn adding_and_removing_a_group_member() {
        let repository_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let created = created_event(repository_id, RepositoryType::Group);
        let repo = PackageRepository::from_events(&[created.clone()]);
        let added = repo.add_group_member(member_id, 0).unwrap();
        let repo = PackageRepository::from_events(&[created.clone(), added.clone()]);
        assert_eq!(repo.group_members, vec![(member_id, 0)]);

        let removed = repo.remove_group_member(member_id).unwrap();
        let repo = PackageRepository::from_events(&[created, added, removed]);
        assert!(repo.group_members.is_empty());
    }

    #[test]
    fn deleting_prevents_further_mutation() {
        let repository_id = Uuid::new_v4();
        let created = created_event(repository_id, RepositoryType::Hosted);
        let repo = PackageRepository::from_events(&[created.clone()]);
        let deleted = repo.delete().unwrap();
        let repo = PackageRepository::from_events(&[created, deleted]);
        assert!(repo.deleted);
        let err = repo.rename("x".to_string()).unwrap_err();
        assert!(matches!(err, DomainError::AlreadyDeleted));
    }

    #[test]
    fn setting_and_clearing_a_retention_policy() {
        let repository_id = Uuid::new_v4();
        let created = created_event(repository_id, RepositoryType::Hosted);
        let repo = PackageRepository::from_events(&[created.clone()]);
        assert_eq!(repo.retention_keep_last_n, None);

        let set = repo.set_retention_policy(Some(5)).unwrap();
        let repo = PackageRepository::from_events(&[created.clone(), set]);
        assert_eq!(repo.retention_keep_last_n, Some(5));

        let cleared = repo.set_retention_policy(None).unwrap();
        let repo = PackageRepository::from_events(&[created, cleared]);
        assert_eq!(repo.retention_keep_last_n, None);
    }

    #[test]
    fn setting_a_retention_policy_below_one_is_rejected() {
        let repository_id = Uuid::new_v4();
        let repo = PackageRepository::from_events(&[created_event(repository_id, RepositoryType::Hosted)]);
        let err = repo.set_retention_policy(Some(0)).unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));
    }
}
