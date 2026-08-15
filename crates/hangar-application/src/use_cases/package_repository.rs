use std::sync::Arc;

use hangar_domain::error::DomainError;
use hangar_domain::package_repository::{
    parse_repository_name, PackageRepository, PackageRepositoryEventStorePort,
    PackageRepositoryQueryPort, RepositoryFormat, RepositoryType,
};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct CreatePackageRepositoryUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
    query: Arc<dyn PackageRepositoryQueryPort>,
}

impl CreatePackageRepositoryUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>, query: Arc<dyn PackageRepositoryQueryPort>) -> Self {
        Self { events, query }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        organization_id: Uuid,
        name: &str,
        format: RepositoryFormat,
        repo_type: RepositoryType,
        remote_url: Option<String>,
        remote_username: Option<String>,
        remote_password: Option<String>,
        actor_id: Uuid,
    ) -> Result<Uuid, ApplicationError> {
        let name = parse_repository_name(name)?;
        if self.query.find_by_org_and_name(organization_id, &name).await?.is_some() {
            return Err(ApplicationError::RepositoryNameTaken);
        }
        let repository_id = Uuid::new_v4();
        let event = PackageRepository::create(repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password);
        self.events.append(repository_id, 0, vec![event], actor_id).await?;
        Ok(repository_id)
    }
}

pub struct RenamePackageRepositoryUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
    query: Arc<dyn PackageRepositoryQueryPort>,
}

impl RenamePackageRepositoryUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>, query: Arc<dyn PackageRepositoryQueryPort>) -> Self {
        Self { events, query }
    }

    pub async fn execute(&self, repository_id: Uuid, new_name: &str, actor_id: Uuid) -> Result<(), ApplicationError> {
        let new_name = parse_repository_name(new_name)?;
        // Fetch-then-check: the repository being renamed carries its own organization_id, which scopes the name-uniqueness check below.
        if let Some(current) = self.query.find_by_id(repository_id).await? {
            // Renaming to your own current name stays a no-op rather than a conflict.
            if let Some(existing) = self.query.find_by_org_and_name(current.organization_id, &new_name).await? {
                if existing.id != repository_id {
                    return Err(ApplicationError::RepositoryNameTaken);
                }
            }
        }
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        let event = repo.rename(new_name)?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct DeletePackageRepositoryUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
}

impl DeletePackageRepositoryUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>) -> Self {
        Self { events }
    }

    pub async fn execute(&self, repository_id: Uuid, actor_id: Uuid) -> Result<(), ApplicationError> {
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        let event = repo.delete()?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct AddGroupMemberUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
    query: Arc<dyn PackageRepositoryQueryPort>,
}

impl AddGroupMemberUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>, query: Arc<dyn PackageRepositoryQueryPort>) -> Self {
        Self { events, query }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        member_repository_id: Uuid,
        position: i32,
        actor_id: Uuid,
    ) -> Result<(), ApplicationError> {
        // Only direct self-membership is rejected — transitive cycles are out of scope.
        if member_repository_id == repository_id {
            return Err(DomainError::SelfGroupMembership.into());
        }
        let Some(member) = self.query.find_by_id(member_repository_id).await? else {
            return Err(DomainError::UnknownGroupMember(member_repository_id).into());
        };
        // Fetch-then-check, same pattern as the format check below: a group must not gain a member from a different organization.
        if let Some(group) = self.query.find_by_id(repository_id).await? {
            if group.organization_id != member.organization_id {
                return Err(DomainError::GroupMemberOrganizationMismatch(member_repository_id).into());
            }
        }
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        // A group mixing formats would silently serve the wrong content for mismatched members.
        if repo.format.is_some_and(|group_format| group_format != member.format) {
            return Err(DomainError::GroupMemberFormatMismatch(member_repository_id).into());
        }
        let event = repo.add_group_member(member_repository_id, position)?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct RemoveGroupMemberUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
}

impl RemoveGroupMemberUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>) -> Self {
        Self { events }
    }

    pub async fn execute(&self, repository_id: Uuid, member_repository_id: Uuid, actor_id: Uuid) -> Result<(), ApplicationError> {
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        let event = repo.remove_group_member(member_repository_id)?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct SetRepositoryQuotaUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
}

impl SetRepositoryQuotaUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>) -> Self {
        Self { events }
    }

    /// `quota_bytes: None` clears the quota (unlimited).
    pub async fn execute(&self, repository_id: Uuid, quota_bytes: Option<i64>, actor_id: Uuid) -> Result<(), ApplicationError> {
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        let event = repo.set_quota(quota_bytes)?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct SetRetentionPolicyUseCase {
    events: Arc<dyn PackageRepositoryEventStorePort>,
}

impl SetRetentionPolicyUseCase {
    pub fn new(events: Arc<dyn PackageRepositoryEventStorePort>) -> Self {
        Self { events }
    }

    /// `keep_last_n_versions: None` disables automatic cleanup.
    pub async fn execute(&self, repository_id: Uuid, keep_last_n_versions: Option<i32>, actor_id: Uuid) -> Result<(), ApplicationError> {
        let (version, past_events) = self.events.load(repository_id).await?;
        let repo = PackageRepository::from_events(&past_events);
        let event = repo.set_retention_policy(keep_last_n_versions)?;
        self.events.append(repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hangar_domain::error::EventStoreError;
    use hangar_domain::package_repository::{PackageRepositoryEvent, PackageRepositorySummary};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A fixed organization id for tests that don't specifically exercise multi-org behavior — the fake store has no FK constraints, so any value works.
    const ORG_ID: Uuid = Uuid::from_u128(1);
    const OTHER_ORG_ID: Uuid = Uuid::from_u128(2);

    struct FakePackageRepositoryStore {
        streams: Mutex<HashMap<Uuid, Vec<PackageRepositoryEvent>>>,
    }

    impl FakePackageRepositoryStore {
        fn new() -> Self {
            Self { streams: Mutex::new(HashMap::new()) }
        }

        fn summarize(id: Uuid, events: &[PackageRepositoryEvent]) -> Option<PackageRepositorySummary> {
            let repo = PackageRepository::from_events(events);
            if repo.deleted || repo.name.is_none() {
                return None;
            }
            // The aggregate itself doesn't track organization_id, so pull it from the Created
            // event, mirroring how the real Postgres projection persists it as its own column.
            let organization_id = events
                .iter()
                .find_map(|event| match event {
                    PackageRepositoryEvent::Created { organization_id, .. } => Some(*organization_id),
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
    impl PackageRepositoryEventStorePort for FakePackageRepositoryStore {
        async fn load(&self, repository_id: Uuid) -> Result<(u64, Vec<PackageRepositoryEvent>), EventStoreError> {
            let streams = self.streams.lock().unwrap();
            let events = streams.get(&repository_id).cloned().unwrap_or_default();
            Ok((events.len() as u64, events))
        }

        async fn append(
            &self,
            repository_id: Uuid,
            expected_version: u64,
            events: Vec<PackageRepositoryEvent>,
            _actor_id: Uuid,
        ) -> Result<(), EventStoreError> {
            let mut streams = self.streams.lock().unwrap();
            let stream = streams.entry(repository_id).or_default();
            if stream.len() as u64 != expected_version {
                return Err(EventStoreError::ConcurrencyConflict {
                    expected: expected_version,
                    actual: stream.len() as u64,
                });
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
            Ok(streams.iter().find_map(|(id, events)| {
                Self::summarize(*id, events).filter(|s| s.organization_id == organization_id && s.name == name)
            }))
        }

        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams.iter().filter_map(|(id, events)| Self::summarize(*id, events)).collect())
        }
    }

    #[tokio::test]
    async fn creates_a_hosted_repository() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let use_case = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = use_case
            .execute(ORG_ID, "my-npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let summary = store.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(summary.name, "my-npm-repo");
    }

    #[tokio::test]
    async fn rejects_a_duplicate_name() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let use_case = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        use_case.execute(ORG_ID, "dup", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        let err = use_case
            .execute(ORG_ID, "dup", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(matches!(err, ApplicationError::RepositoryNameTaken));
    }

    #[tokio::test]
    async fn the_same_name_is_reusable_across_different_organizations() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let use_case = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        use_case.execute(ORG_ID, "shared-name", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        let other_org_id = use_case
            .execute(OTHER_ORG_ID, "shared-name", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(store.find_by_id(other_org_id).await.unwrap().unwrap().organization_id, OTHER_ORG_ID);
    }

    #[tokio::test]
    async fn renames_a_repository() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create
            .execute(ORG_ID, "old-name", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let rename = RenamePackageRepositoryUseCase::new(store.clone(), store.clone());
        rename.execute(id, "new-name", Uuid::new_v4()).await.unwrap();

        let summary = store.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(summary.name, "new-name");
    }

    #[tokio::test]
    async fn rejects_renaming_onto_another_repositorys_name() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        create.execute(ORG_ID, "taken", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        let id = create
            .execute(ORG_ID, "mine", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let rename = RenamePackageRepositoryUseCase::new(store.clone(), store.clone());
        let err = rename.execute(id, "taken", Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::RepositoryNameTaken));
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().name, "mine");
    }

    #[tokio::test]
    async fn allows_renaming_onto_a_deleted_repositorys_name() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let gone_id = create
            .execute(ORG_ID, "recycled", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let id = create
            .execute(ORG_ID, "mine", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        DeletePackageRepositoryUseCase::new(store.clone()).execute(gone_id, Uuid::new_v4()).await.unwrap();

        let rename = RenamePackageRepositoryUseCase::new(store.clone(), store.clone());
        rename.execute(id, "recycled", Uuid::new_v4()).await.unwrap();

        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().name, "recycled");
    }

    #[tokio::test]
    async fn adds_and_removes_a_group_member() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let group_id = create
            .execute(ORG_ID, "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let member_id = create
            .execute(ORG_ID, "member-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        add.execute(group_id, member_id, 0, Uuid::new_v4()).await.unwrap();
        let summary = store.find_by_id(group_id).await.unwrap().unwrap();
        assert_eq!(summary.group_members, vec![member_id]);

        let remove = RemoveGroupMemberUseCase::new(store.clone());
        remove.execute(group_id, member_id, Uuid::new_v4()).await.unwrap();
        let summary = store.find_by_id(group_id).await.unwrap().unwrap();
        assert!(summary.group_members.is_empty());
    }

    #[tokio::test]
    async fn a_group_cannot_contain_itself() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let group_id = create
            .execute(ORG_ID, "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        let err = add.execute(group_id, group_id, 0, Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::SelfGroupMembership)), "got {err:?}");
        assert!(store.find_by_id(group_id).await.unwrap().unwrap().group_members.is_empty());
    }

    #[tokio::test]
    async fn a_nonexistent_member_repository_is_rejected() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let group_id = create
            .execute(ORG_ID, "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let ghost_id = Uuid::new_v4();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        let err = add.execute(group_id, ghost_id, 0, Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::UnknownGroupMember(id)) if id == ghost_id), "got {err:?}");
        assert!(store.find_by_id(group_id).await.unwrap().unwrap().group_members.is_empty());
    }

    #[tokio::test]
    async fn a_member_with_a_different_format_than_the_group_is_rejected() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let npm_group_id = create
            .execute(ORG_ID, "npm-group", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let docker_member_id = create
            .execute(ORG_ID, "docker-member", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        let err = add.execute(npm_group_id, docker_member_id, 0, Uuid::new_v4()).await.unwrap_err();

        assert!(
            matches!(err, ApplicationError::Domain(DomainError::GroupMemberFormatMismatch(id)) if id == docker_member_id),
            "got {err:?}"
        );
        assert!(store.find_by_id(npm_group_id).await.unwrap().unwrap().group_members.is_empty());
    }

    #[tokio::test]
    async fn a_member_from_a_different_organization_than_the_group_is_rejected() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let group_id = create
            .execute(ORG_ID, "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let other_org_member_id = create
            .execute(OTHER_ORG_ID, "other-org-member", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        let err = add.execute(group_id, other_org_member_id, 0, Uuid::new_v4()).await.unwrap_err();

        assert!(
            matches!(err, ApplicationError::Domain(DomainError::GroupMemberOrganizationMismatch(id)) if id == other_org_member_id),
            "got {err:?}"
        );
        assert!(store.find_by_id(group_id).await.unwrap().unwrap().group_members.is_empty());
    }

    #[tokio::test]
    async fn a_deleted_repository_cannot_be_added_as_a_member() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let group_id = create
            .execute(ORG_ID, "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let gone_id = create
            .execute(ORG_ID, "gone-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        DeletePackageRepositoryUseCase::new(store.clone()).execute(gone_id, Uuid::new_v4()).await.unwrap();

        let add = AddGroupMemberUseCase::new(store.clone(), store.clone());
        let err = add.execute(group_id, gone_id, 0, Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::UnknownGroupMember(_))), "got {err:?}");
    }

    #[tokio::test]
    async fn mutating_a_deleted_repository_fails() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create
            .execute(ORG_ID, "to-delete", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();

        let delete = DeletePackageRepositoryUseCase::new(store.clone());
        delete.execute(id, Uuid::new_v4()).await.unwrap();

        let rename = RenamePackageRepositoryUseCase::new(store.clone(), store.clone());
        let err = rename.execute(id, "too-late", Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(_)));
    }

    #[tokio::test]
    async fn sets_and_clears_a_repository_quota() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create.execute(ORG_ID, "quota-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, None);

        let set_quota = SetRepositoryQuotaUseCase::new(store.clone());
        set_quota.execute(id, Some(1_000_000), Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, Some(1_000_000));

        set_quota.execute(id, None, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().quota_bytes, None);
    }

    #[tokio::test]
    async fn setting_a_negative_quota_is_rejected() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create.execute(ORG_ID, "quota-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();

        let set_quota = SetRepositoryQuotaUseCase::new(store.clone());
        let err = set_quota.execute(id, Some(-1), Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::Validation(_))), "got {err:?}");
    }

    #[tokio::test]
    async fn setting_a_quota_on_a_deleted_repository_fails() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create.execute(ORG_ID, "to-delete", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        DeletePackageRepositoryUseCase::new(store.clone()).execute(id, Uuid::new_v4()).await.unwrap();

        let set_quota = SetRepositoryQuotaUseCase::new(store.clone());
        let err = set_quota.execute(id, Some(1024), Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(_)));
    }

    #[tokio::test]
    async fn sets_and_clears_a_retention_policy() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create.execute(ORG_ID, "retention-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, None);

        let set_retention = SetRetentionPolicyUseCase::new(store.clone());
        set_retention.execute(id, Some(3), Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, Some(3));

        set_retention.execute(id, None, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_by_id(id).await.unwrap().unwrap().retention_keep_last_n, None);
    }

    #[tokio::test]
    async fn setting_a_retention_policy_below_one_is_rejected() {
        let store = Arc::new(FakePackageRepositoryStore::new());
        let create = CreatePackageRepositoryUseCase::new(store.clone(), store.clone());
        let id = create.execute(ORG_ID, "retention-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4()).await.unwrap();

        let set_retention = SetRetentionPolicyUseCase::new(store.clone());
        let err = set_retention.execute(id, Some(0), Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::Validation(_))), "got {err:?}");
    }
}
