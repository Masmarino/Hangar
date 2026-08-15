use std::sync::Arc;

use hangar_domain::error::DomainError;
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use hangar_domain::permission::{Permission, PermissionEventStorePort, Role};
use hangar_domain::user::UserRepositoryPort;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct GrantPermissionUseCase {
    events: Arc<dyn PermissionEventStorePort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    users: Arc<dyn UserRepositoryPort>,
}

impl GrantPermissionUseCase {
    pub fn new(events: Arc<dyn PermissionEventStorePort>, repositories: Arc<dyn PackageRepositoryQueryPort>, users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { events, repositories, users }
    }

    pub async fn execute(&self, user_id: Uuid, repository_id: Uuid, role: Role, actor_id: Uuid) -> Result<(), ApplicationError> {
        // A grantee outside the repository's own organization must be rejected here regardless
        // of what the route already checked — a super-admin grantee legitimately operates cross-org.
        let (repo, grantee) = tokio::join!(self.repositories.find_by_id(repository_id), self.users.find_by_id(user_id));
        let mismatch = match (repo?, grantee?) {
            (Some(repo), Some(grantee)) => !grantee.is_super_admin && grantee.organization_id != repo.organization_id,
            _ => false,
        };
        if mismatch {
            return Err(DomainError::GranteeOrganizationMismatch(user_id).into());
        }
        let (version, past_events) = self.events.load(user_id, repository_id).await?;
        let permission = Permission::from_events(&past_events);
        let event = permission.grant(user_id, repository_id, role);
        self.events.append(user_id, repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

pub struct RevokePermissionUseCase {
    events: Arc<dyn PermissionEventStorePort>,
}

impl RevokePermissionUseCase {
    pub fn new(events: Arc<dyn PermissionEventStorePort>) -> Self {
        Self { events }
    }

    pub async fn execute(&self, user_id: Uuid, repository_id: Uuid, actor_id: Uuid) -> Result<(), ApplicationError> {
        let (version, past_events) = self.events.load(user_id, repository_id).await?;
        let permission = Permission::from_events(&past_events);
        let event = permission.revoke(user_id, repository_id)?;
        self.events.append(user_id, repository_id, version, vec![event], actor_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use hangar_domain::error::EventStoreError;
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
    // Only the test double implements the query side; the use cases here are
    // write-only, so this import stays scoped to the tests.
    use hangar_domain::permission::{PermissionEvent, PermissionQueryPort};
    use hangar_domain::user::{User, Username};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeRepositories {
        repos: Mutex<HashMap<Uuid, PackageRepositorySummary>>,
    }

    impl FakeRepositories {
        fn new() -> Self {
            Self { repos: Mutex::new(HashMap::new()) }
        }

        fn insert(&self, id: Uuid, organization_id: Uuid) {
            self.repos.lock().unwrap().insert(
                id,
                PackageRepositorySummary {
                    id,
                    organization_id,
                    name: "repo".to_string(),
                    format: RepositoryFormat::Npm,
                    repo_type: RepositoryType::Hosted,
                    remote_url: None,
                    remote_username: None,
                    remote_password: None,
                    group_members: Vec::new(),
                    quota_bytes: None,
                    retention_keep_last_n: None,
                },
            );
        }
    }

    #[async_trait]
    impl PackageRepositoryQueryPort for FakeRepositories {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            Ok(self.repos.lock().unwrap().get(&id).cloned())
        }

        async fn find_by_org_and_name(&self, _organization_id: Uuid, _name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
            unreachable!("not exercised by this use case's tests")
        }
    }

    struct FakeUsers {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl FakeUsers {
        fn new() -> Self {
            Self { users: Mutex::new(HashMap::new()) }
        }

        fn insert(&self, id: Uuid, organization_id: Uuid, is_super_admin: bool) {
            self.users.lock().unwrap().insert(
                id,
                User {
                    id,
                    username: Username::parse("grantee-user").unwrap(),
                    password_hash: String::new(),
                    is_super_admin,
                    is_organization_admin: false,
                    organization_id,
                    created_at: Utc::now(),
                    tokens_valid_after: Utc::now(),
                    email: None,
                },
            );
        }
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().get(&id).cloned())
        }

        async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn find_by_email(&self, _email: &str) -> Result<Option<User>, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn list_all(&self) -> Result<Vec<User>, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn insert(&self, _user: &User) -> Result<(), DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn delete(&self, _id: Uuid) -> Result<(), DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn update_password(&self, _id: Uuid, _new_password_hash: String) -> Result<(), DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn set_super_admin(&self, _id: Uuid, _is_super_admin: bool) -> Result<(), DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn set_organization_admin(&self, _id: Uuid, _is_organization_admin: bool) -> Result<(), DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn delete_unless_last_super_admin(&self, _id: Uuid) -> Result<bool, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn set_super_admin_unless_last(&self, _id: Uuid, _is_super_admin: bool) -> Result<bool, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }
    }

    /// No repository/user registered in either fake, so `execute`'s lookups both come back
    /// `None` and the organization check is skipped — same behavior the pre-fix use case had
    /// for every test below, which only exercise the grant/revoke event-sourcing mechanics.
    fn use_case_without_organization_data(store: Arc<FakePermissionStore>) -> GrantPermissionUseCase {
        GrantPermissionUseCase::new(store, Arc::new(FakeRepositories::new()), Arc::new(FakeUsers::new()))
    }

    struct FakePermissionStore {
        streams: Mutex<HashMap<(Uuid, Uuid), Vec<PermissionEvent>>>,
    }

    impl FakePermissionStore {
        fn new() -> Self {
            Self { streams: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl PermissionEventStorePort for FakePermissionStore {
        async fn load(&self, user_id: Uuid, repository_id: Uuid) -> Result<(u64, Vec<PermissionEvent>), EventStoreError> {
            let streams = self.streams.lock().unwrap();
            let events = streams.get(&(user_id, repository_id)).cloned().unwrap_or_default();
            Ok((events.len() as u64, events))
        }

        async fn append(
            &self,
            user_id: Uuid,
            repository_id: Uuid,
            expected_version: u64,
            events: Vec<PermissionEvent>,
            _actor_id: Uuid,
        ) -> Result<(), EventStoreError> {
            let mut streams = self.streams.lock().unwrap();
            let stream = streams.entry((user_id, repository_id)).or_default();
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
    impl PermissionQueryPort for FakePermissionStore {
        async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            let events = streams.get(&(user_id, repository_id)).cloned().unwrap_or_default();
            Ok(Permission::from_events(&events).role)
        }

        async fn list_for_repository(&self, repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams
                .iter()
                .filter(|((_, repo_id), _)| *repo_id == repository_id)
                .filter_map(|((user_id, _), events)| Permission::from_events(events).role.map(|role| (*user_id, role)))
                .collect())
        }

        async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams
                .iter()
                .filter_map(|((user_id, repository_id), events)| Permission::from_events(events).role.map(|role| (*user_id, *repository_id, role)))
                .collect())
        }

        async fn count_all(&self) -> Result<usize, EventStoreError> {
            unreachable!("not exercised by this use case's tests")
        }

        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            let streams = self.streams.lock().unwrap();
            Ok(streams
                .iter()
                .filter(|((uid, _), _)| *uid == user_id)
                .filter_map(|((_, repo_id), events)| Permission::from_events(events).role.map(|role| (*repo_id, role)))
                .collect())
        }
    }

    #[tokio::test]
    async fn grants_a_role() {
        let store = Arc::new(FakePermissionStore::new());
        let use_case = use_case_without_organization_data(store.clone());
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        use_case.execute(user_id, repository_id, Role::Write, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), Some(Role::Write));
    }

    #[tokio::test]
    async fn re_granting_replaces_the_role() {
        let store = Arc::new(FakePermissionStore::new());
        let use_case = use_case_without_organization_data(store.clone());
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        use_case.execute(user_id, repository_id, Role::Read, Uuid::new_v4()).await.unwrap();
        use_case.execute(user_id, repository_id, Role::Admin, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), Some(Role::Admin));
    }

    #[tokio::test]
    async fn revokes_a_granted_role() {
        let store = Arc::new(FakePermissionStore::new());
        let grant = use_case_without_organization_data(store.clone());
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        grant.execute(user_id, repository_id, Role::Read, Uuid::new_v4()).await.unwrap();

        let revoke = RevokePermissionUseCase::new(store.clone());
        revoke.execute(user_id, repository_id, Uuid::new_v4()).await.unwrap();
        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn revoking_without_a_prior_grant_fails() {
        let store = Arc::new(FakePermissionStore::new());
        let revoke = RevokePermissionUseCase::new(store.clone());
        let err = revoke.execute(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(_)));
    }

    #[tokio::test]
    async fn granting_to_a_user_in_a_different_organization_than_the_repository_is_rejected() {
        let store = Arc::new(FakePermissionStore::new());
        let repositories = Arc::new(FakeRepositories::new());
        let users = Arc::new(FakeUsers::new());
        let repository_id = Uuid::new_v4();
        let repo_org_id = Uuid::new_v4();
        repositories.insert(repository_id, repo_org_id);
        let user_id = Uuid::new_v4();
        users.insert(user_id, Uuid::new_v4(), false); // a different organization than the repository
        let use_case = GrantPermissionUseCase::new(store.clone(), repositories, users);

        let err = use_case.execute(user_id, repository_id, Role::Write, Uuid::new_v4()).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::GranteeOrganizationMismatch(id)) if id == user_id));
        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn granting_to_a_user_in_the_same_organization_as_the_repository_still_works() {
        let store = Arc::new(FakePermissionStore::new());
        let repositories = Arc::new(FakeRepositories::new());
        let users = Arc::new(FakeUsers::new());
        let organization_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        repositories.insert(repository_id, organization_id);
        let user_id = Uuid::new_v4();
        users.insert(user_id, organization_id, false);
        let use_case = GrantPermissionUseCase::new(store.clone(), repositories, users);

        use_case.execute(user_id, repository_id, Role::Write, Uuid::new_v4()).await.unwrap();

        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), Some(Role::Write));
    }

    #[tokio::test]
    async fn a_super_admin_can_be_granted_a_permission_across_organizations() {
        let store = Arc::new(FakePermissionStore::new());
        let repositories = Arc::new(FakeRepositories::new());
        let users = Arc::new(FakeUsers::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(repository_id, Uuid::new_v4());
        let user_id = Uuid::new_v4();
        users.insert(user_id, Uuid::new_v4(), true); // super-admin, unrelated organization
        let use_case = GrantPermissionUseCase::new(store.clone(), repositories, users);

        use_case.execute(user_id, repository_id, Role::Admin, Uuid::new_v4()).await.unwrap();

        assert_eq!(store.find_role(user_id, repository_id).await.unwrap(), Some(Role::Admin));
    }
}
