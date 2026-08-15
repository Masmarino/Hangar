use std::sync::Arc;

use chrono::Utc;
use hangar_domain::api_token::ApiTokenRepositoryPort;
use hangar_domain::docker_registry::{DockerGrantedScope, DockerScopeRequest, DockerTokenIssuerPort};
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use hangar_domain::permission::{PermissionQueryPort, Role, organization_admin_bypass_role};
use hangar_domain::user::{User, UserRepositoryPort};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::api_token::hash_api_token;

pub struct IssueDockerAccessTokenUseCase {
    api_tokens: Arc<dyn ApiTokenRepositoryPort>,
    users: Arc<dyn UserRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    permissions: Arc<dyn PermissionQueryPort>,
    token_issuer: Arc<dyn DockerTokenIssuerPort>,
}

impl IssueDockerAccessTokenUseCase {
    pub fn new(
        api_tokens: Arc<dyn ApiTokenRepositoryPort>,
        users: Arc<dyn UserRepositoryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        permissions: Arc<dyn PermissionQueryPort>,
        token_issuer: Arc<dyn DockerTokenIssuerPort>,
    ) -> Self {
        Self { api_tokens, users, repositories, permissions, token_issuer }
    }

    /// `password` is the caller's Hangar API token — the Basic-auth username is never checked.
    /// `organization_id` is the registry subdomain requested against, not necessarily the user's own.
    pub async fn execute(&self, organization_id: Uuid, password: &str, scope: Option<&str>) -> Result<String, ApplicationError> {
        let hash = hash_api_token(password);
        let token = self.api_tokens.find_by_hash(&hash).await?.ok_or(ApplicationError::InvalidCredentials)?;
        if !token.is_active() {
            return Err(ApplicationError::InvalidCredentials);
        }
        let _ = self.api_tokens.touch_last_used_at(token.id, Utc::now()).await;
        let user = self.users.find_by_id(token.user_id).await?.ok_or(ApplicationError::InvalidCredentials)?;

        let granted_scope = match scope.and_then(DockerScopeRequest::parse) {
            None => None,
            Some(requested) => Some(self.authorize(organization_id, &user, &requested).await?),
        };

        Ok(self.token_issuer.issue(user.id, user.organization_id, user.is_super_admin, granted_scope)?)
    }

    /// Never errors for an under-authorized request — mirrors real Docker registries by returning a reduced scope instead, without revealing whether a missing repository exists.
    async fn authorize(&self, organization_id: Uuid, user: &User, requested: &DockerScopeRequest) -> Result<DockerGrantedScope, ApplicationError> {
        let repository = self.repositories.find_by_org_and_name(organization_id, requested.hangar_repository_name()).await?;

        let (actions, granted_repository_id) = match &repository {
            None => (vec![], None),
            Some(repository) => {
                let role = if user.is_super_admin {
                    Some(Role::Admin)
                } else if let Some(role) = organization_admin_bypass_role(user.is_organization_admin, user.organization_id, repository.organization_id) {
                    Some(role)
                } else {
                    self.permissions.find_role(user.id, repository.id).await?
                };
                let actions =
                    requested.actions.iter().filter(|action| role.is_some_and(|role| role.satisfies(required_role_for_action(action)))).cloned().collect();
                (actions, Some(repository.id))
            }
        };

        Ok(DockerGrantedScope { resource_type: requested.resource_type.clone(), name: requested.name.clone(), actions, granted_repository_id })
    }
}

/// Unrecognized actions fail closed to write access rather than silently granting them.
fn required_role_for_action(action: &str) -> Role {
    if action == "pull" { Role::Read } else { Role::Write }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hangar_domain::api_token::ApiToken;
    use hangar_domain::docker_registry::DockerAccessClaims;
    use hangar_domain::error::{DomainError, EventStoreError};
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
    use hangar_domain::permission::Role;
    use hangar_domain::user::{User, Username};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    struct FakeApiTokens(Mutex<HashMap<String, ApiToken>>);
    #[async_trait]
    impl ApiTokenRepositoryPort for FakeApiTokens {
        async fn insert(&self, token: &ApiToken) -> Result<(), DomainError> {
            self.0.lock().unwrap().insert(token.token_hash.clone(), token.clone());
            Ok(())
        }
        async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<ApiToken>, DomainError> { Ok(vec![]) }
        async fn list_all(&self) -> Result<Vec<ApiToken>, DomainError> { Ok(vec![]) }
        async fn find_by_hash(&self, token_hash: &str) -> Result<Option<ApiToken>, DomainError> {
            Ok(self.0.lock().unwrap().get(token_hash).cloned())
        }
        async fn touch_last_used_at(&self, _id: Uuid, _used_at: chrono::DateTime<chrono::Utc>) -> Result<(), DomainError> { Ok(()) }
        async fn revoke(&self, _id: Uuid, _user_id: Uuid) -> Result<bool, DomainError> { Ok(true) }
        async fn revoke_any(&self, _id: Uuid) -> Result<(), DomainError> { Ok(()) }
    }

    struct FakeUsers(Mutex<HashMap<Uuid, User>>);
    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> { Ok(self.0.lock().unwrap().get(&id).cloned()) }
        async fn find_by_username(&self, _username: &Username) -> Result<Option<User>, DomainError> { Ok(None) }
        async fn find_by_email(&self, _email: &str) -> Result<Option<User>, DomainError> { Ok(None) }
        async fn list_all(&self) -> Result<Vec<User>, DomainError> { Ok(vec![]) }
        async fn insert(&self, user: &User) -> Result<(), DomainError> {
            self.0.lock().unwrap().insert(user.id, user.clone());
            Ok(())
        }
        async fn delete(&self, _id: Uuid) -> Result<(), DomainError> { Ok(()) }
        async fn update_password(&self, _id: Uuid, _new_password_hash: String) -> Result<(), DomainError> { Ok(()) }
        async fn set_super_admin(&self, _id: Uuid, _is_super_admin: bool) -> Result<(), DomainError> { Ok(()) }
        async fn set_organization_admin(&self, _id: Uuid, _is_organization_admin: bool) -> Result<(), DomainError> { Ok(()) }
        async fn delete_unless_last_super_admin(&self, _id: Uuid) -> Result<bool, DomainError> { Ok(true) }
        async fn set_super_admin_unless_last(&self, _id: Uuid, _is_super_admin: bool) -> Result<bool, DomainError> { Ok(true) }
    }

    // Keyed by (organization_id, name), not name alone — names are only unique per-org, and the cross-org test below relies on seeding two same-named repos.
    struct FakeRepositories(Mutex<HashMap<(Uuid, String), PackageRepositorySummary>>);
    #[async_trait]
    impl PackageRepositoryQueryPort for FakeRepositories {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            Ok(self.0.lock().unwrap().values().find(|r| r.id == id).cloned())
        }
        async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            Ok(self.0.lock().unwrap().get(&(organization_id, name.to_string())).cloned())
        }
        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> { Ok(self.0.lock().unwrap().values().cloned().collect()) }
    }

    struct FakePermissions(Mutex<HashMap<(Uuid, Uuid), Role>>);
    #[async_trait]
    impl PermissionQueryPort for FakePermissions {
        async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError> {
            Ok(self.0.lock().unwrap().get(&(user_id, repository_id)).copied())
        }
        async fn list_for_repository(&self, _repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> { Ok(vec![]) }
        async fn list_for_user(&self, _user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> { Ok(vec![]) }
        async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError> { unreachable!("not exercised by this use case's tests") }
        async fn count_all(&self) -> Result<usize, EventStoreError> { unreachable!("not exercised by this use case's tests") }
    }

    struct FakeTokenIssuer(Mutex<Option<(Uuid, Option<DockerGrantedScope>)>>);
    #[async_trait]
    impl DockerTokenIssuerPort for FakeTokenIssuer {
        fn issue(&self, user_id: Uuid, _organization_id: Uuid, _is_super_admin: bool, granted_scope: Option<DockerGrantedScope>) -> Result<String, DomainError> {
            *self.0.lock().unwrap() = Some((user_id, granted_scope));
            Ok("fake-jwt".to_string())
        }
        fn verify(&self, _token: &str) -> Result<DockerAccessClaims, DomainError> {
            unreachable!("not exercised by this use case's tests")
        }
    }

    fn active_token(user_id: Uuid) -> ApiToken {
        ApiToken { id: Uuid::new_v4(), user_id, token_hash: hash_api_token("plaintext-token"), label: "ci".into(), created_at: chrono::Utc::now(), last_used_at: None, revoked_at: None }
    }

    /// Fixed so tests can insert repositories in the test user's own org without threading an id through every call site.
    const ORG_ID: Uuid = Uuid::from_u128(1);

    fn regular_user(id: Uuid) -> User {
        User { id, username: Username::parse("alice").unwrap(), password_hash: "irrelevant".into(), is_super_admin: false, is_organization_admin: false, organization_id: ORG_ID, created_at: chrono::Utc::now(), tokens_valid_after: chrono::Utc::now(), email: None }
    }

    struct Harness {
        use_case: IssueDockerAccessTokenUseCase,
        repositories: Arc<FakeRepositories>,
        permissions: Arc<FakePermissions>,
        issuer: Arc<FakeTokenIssuer>,
        user_id: Uuid,
    }

    fn harness(user: User) -> Harness {
        let user_id = user.id;
        let api_tokens = Arc::new(FakeApiTokens(Mutex::new(HashMap::from([(active_token(user_id).token_hash.clone(), active_token(user_id))]))));
        let users = Arc::new(FakeUsers(Mutex::new(HashMap::from([(user_id, user)]))));
        let repositories = Arc::new(FakeRepositories(Mutex::new(HashMap::new())));
        let permissions = Arc::new(FakePermissions(Mutex::new(HashMap::new())));
        let issuer = Arc::new(FakeTokenIssuer(Mutex::new(None)));
        let use_case = IssueDockerAccessTokenUseCase::new(api_tokens, users, repositories.clone(), permissions.clone(), issuer.clone());
        Harness { use_case, repositories, permissions, issuer, user_id }
    }

    #[tokio::test]
    async fn rejects_an_unknown_token() {
        let h = harness(regular_user(Uuid::new_v4()));
        let result = h.use_case.execute(ORG_ID, "wrong-token", None).await;
        assert!(matches!(result, Err(ApplicationError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn issues_a_token_with_no_granted_scope_when_none_was_requested() {
        let h = harness(regular_user(Uuid::new_v4()));
        h.use_case.execute(ORG_ID, "plaintext-token", None).await.unwrap();
        let (issued_for, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(issued_for, h.user_id);
        assert!(granted.is_none());
    }

    #[tokio::test]
    async fn a_reader_requesting_pull_and_push_is_only_granted_pull() {
        let h = harness(regular_user(Uuid::new_v4()));
        let repo = PackageRepositorySummary { id: Uuid::new_v4(), organization_id: ORG_ID, name: "myrepo".into(), format: RepositoryFormat::Docker, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "myrepo".into()), repo.clone());
        h.permissions.0.lock().unwrap().insert((h.user_id, repo.id), Role::Read);

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:myrepo/myimage:pull,push")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(granted.unwrap().actions, vec!["pull".to_string()]);
    }

    #[tokio::test]
    async fn a_writer_requesting_pull_and_push_is_granted_both() {
        let h = harness(regular_user(Uuid::new_v4()));
        let repo = PackageRepositorySummary { id: Uuid::new_v4(), organization_id: ORG_ID, name: "myrepo".into(), format: RepositoryFormat::Docker, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "myrepo".into()), repo.clone());
        h.permissions.0.lock().unwrap().insert((h.user_id, repo.id), Role::Write);

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:myrepo/myimage:pull,push")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(granted.unwrap().actions, vec!["pull".to_string(), "push".to_string()]);
    }

    #[tokio::test]
    async fn a_nonexistent_repository_grants_no_actions_without_erroring() {
        let h = harness(regular_user(Uuid::new_v4()));
        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:no-such-repo/myimage:pull")).await.unwrap();
        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        let granted = granted.unwrap();
        assert!(granted.actions.is_empty());
        assert!(granted.granted_repository_id.is_none());
    }

    #[tokio::test]
    async fn a_super_admin_is_granted_every_requested_action_without_an_explicit_role() {
        let user_id = Uuid::new_v4();
        let mut admin = regular_user(user_id);
        admin.is_super_admin = true;
        let h = harness(admin);
        let repo = PackageRepositorySummary { id: Uuid::new_v4(), organization_id: ORG_ID, name: "myrepo".into(), format: RepositoryFormat::Docker, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "myrepo".into()), repo);
        // Deliberately no `permissions` entry — the super-admin bypass must not need one.

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:myrepo/myimage:pull,push")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(granted.unwrap().actions, vec!["pull".to_string(), "push".to_string()]);
    }

    /// Mirrors hangar-api's org-admin bypass (`hangar_api::authz::effective_repository_role`) — implicit Admin on any repository in their own org, no explicit grant needed.
    #[tokio::test]
    async fn an_organization_admin_is_granted_every_requested_action_on_a_repository_in_their_own_organization_without_an_explicit_role() {
        let user_id = Uuid::new_v4();
        let mut org_admin = regular_user(user_id);
        org_admin.is_organization_admin = true;
        let h = harness(org_admin);
        let repo = PackageRepositorySummary { id: Uuid::new_v4(), organization_id: ORG_ID, name: "myrepo".into(), format: RepositoryFormat::Docker, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "myrepo".into()), repo);
        // Deliberately no `permissions` entry — the org-admin bypass must not need one.

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:myrepo/myimage:pull,push")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(granted.unwrap().actions, vec!["pull".to_string(), "push".to_string()]);
    }

    #[tokio::test]
    async fn an_organization_admin_of_a_different_organization_gets_no_implicit_role() {
        let user_id = Uuid::new_v4();
        let mut org_admin = regular_user(user_id);
        org_admin.is_organization_admin = true;
        org_admin.organization_id = Uuid::from_u128(999);
        let h = harness(org_admin);
        let repo = PackageRepositorySummary { id: Uuid::new_v4(), organization_id: ORG_ID, name: "myrepo".into(), format: RepositoryFormat::Docker, repo_type: RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![] };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "myrepo".into()), repo);

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:myrepo/myimage:pull")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert!(granted.unwrap().actions.is_empty());
    }

    #[tokio::test]
    async fn a_token_scoped_to_one_organizations_repository_carries_that_repositorys_id() {
        let h = harness(regular_user(Uuid::new_v4()));
        let other_org_id = Uuid::from_u128(2);

        let repo_in_org_a = PackageRepositorySummary {
            id: Uuid::new_v4(),
            organization_id: ORG_ID,
            name: "backend".into(),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None,
            retention_keep_last_n: None,
            group_members: vec![],
        };
        let repo_in_org_b = PackageRepositorySummary {
            id: Uuid::new_v4(),
            organization_id: other_org_id,
            name: "backend".into(),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None,
            retention_keep_last_n: None,
            group_members: vec![],
        };
        h.repositories.0.lock().unwrap().insert((ORG_ID, "backend".into()), repo_in_org_a.clone());
        h.repositories.0.lock().unwrap().insert((other_org_id, "backend".into()), repo_in_org_b.clone());
        h.permissions.0.lock().unwrap().insert((h.user_id, repo_in_org_a.id), Role::Read);
        // Deliberately no permission entry for repo_in_org_b — the id must come from resolving the name against ORG_ID, never a name-only lookup.

        h.use_case.execute(ORG_ID, "plaintext-token", Some("repository:backend/image:pull")).await.unwrap();

        let (_, granted) = h.issuer.0.lock().unwrap().clone().unwrap();
        assert_eq!(granted.unwrap().granted_repository_id, Some(repo_in_org_a.id));
    }
}
