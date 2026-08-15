use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary, RepositoryType};
use uuid::Uuid;

use crate::error::ApplicationError;

/// "Try locally, else recurse into group members" — shared by the 4 GET use cases that hit repository groups. `visited` guards against a cycle.
#[allow(clippy::too_many_arguments)]
pub fn resolve_in_group<'a, T, FHosted, FutHosted, FProxy, FutProxy, FNotFound>(
    repositories: &'a Arc<dyn PackageRepositoryQueryPort>,
    repository_id: Uuid,
    mut visited: HashSet<Uuid>,
    try_hosted: FHosted,
    try_proxy: FProxy,
    not_found: FNotFound,
) -> Pin<Box<dyn Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a>>
where
    T: Send + 'a,
    FHosted: Fn(Uuid) -> FutHosted + Clone + Send + 'a,
    FutHosted: Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a,
    FProxy: Fn(Uuid, PackageRepositorySummary) -> FutProxy + Clone + Send + 'a,
    FutProxy: Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a,
    FNotFound: Fn() -> ApplicationError + Clone + Send + 'a,
{
    Box::pin(async move {
        if !visited.insert(repository_id) {
            return Ok(None);
        }
        let repo = repositories.find_by_id(repository_id).await?.ok_or_else(&not_found)?;
        resolve_fetched(repositories, repo, visited, try_hosted, try_proxy, not_found).await
    })
}

/// Same traversal as [`resolve_in_group`], but for an already-fetched summary — a group's member is never looked up by id twice.
#[allow(clippy::too_many_arguments)]
fn resolve_fetched<'a, T, FHosted, FutHosted, FProxy, FutProxy, FNotFound>(
    repositories: &'a Arc<dyn PackageRepositoryQueryPort>,
    repo: PackageRepositorySummary,
    visited: HashSet<Uuid>,
    try_hosted: FHosted,
    try_proxy: FProxy,
    not_found: FNotFound,
) -> Pin<Box<dyn Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a>>
where
    T: Send + 'a,
    FHosted: Fn(Uuid) -> FutHosted + Clone + Send + 'a,
    FutHosted: Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a,
    FProxy: Fn(Uuid, PackageRepositorySummary) -> FutProxy + Clone + Send + 'a,
    FutProxy: Future<Output = Result<Option<T>, ApplicationError>> + Send + 'a,
    FNotFound: Fn() -> ApplicationError + Clone + Send + 'a,
{
    Box::pin(async move {
        match repo.repo_type {
            RepositoryType::Hosted => try_hosted(repo.id).await,
            RepositoryType::Proxy => try_proxy(repo.id, repo).await,
            RepositoryType::Group => {
                // Fetched concurrently, not one round trip per member.
                let member_ids: Vec<Uuid> = repo.group_members.iter().copied().filter(|id| !visited.contains(id)).collect();
                let members = futures::future::try_join_all(member_ids.iter().map(|&member_id| {
                    let not_found = not_found.clone();
                    async move { repositories.find_by_id(member_id).await?.ok_or_else(&not_found) }
                }))
                .await?;
                // Hosted members go first regardless of stored order — otherwise a proxy member could shadow a private package (dependency confusion).
                let (hosted_first, rest): (Vec<_>, Vec<_>) = members.into_iter().partition(|m| m.repo_type == RepositoryType::Hosted);
                for member in hosted_first.into_iter().chain(rest) {
                    let mut member_visited = visited.clone();
                    member_visited.insert(member.id);
                    let result =
                        resolve_fetched(repositories, member, member_visited, try_hosted.clone(), try_proxy.clone(), not_found.clone()).await?;
                    if result.is_some() {
                        return Ok(result);
                    }
                }
                Ok(None)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use hangar_domain::error::{DomainError, EventStoreError};
    use hangar_domain::package_repository::RepositoryFormat;

    use super::*;
    use crate::use_cases::npm_test_support::FakeRepositories;

    fn hosted_repo(id: Uuid, org: Uuid) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id: org,
            name: format!("hosted-{id}"),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes: None,
            retention_keep_last_n: None,
        }
    }

    fn proxy_repo(id: Uuid, org: Uuid) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id: org,
            name: format!("proxy-{id}"),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            remote_url: Some("https://registry.example/".to_string()),
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes: None,
            retention_keep_last_n: None,
        }
    }

    fn group_repo(id: Uuid, org: Uuid, members: Vec<Uuid>) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id: org,
            name: format!("group-{id}"),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Group,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: members,
            quota_bytes: None,
            retention_keep_last_n: None,
        }
    }

    fn not_found_error() -> ApplicationError {
        ApplicationError::Domain(DomainError::Infrastructure("repository not found".to_string()))
    }

    /// Drives `resolve_in_group` with callbacks that just tag which repository/branch handled the request, so tests can assert on the walk's outcome.
    async fn resolve(repositories: &Arc<dyn PackageRepositoryQueryPort>, repository_id: Uuid) -> Result<Option<String>, ApplicationError> {
        resolve_in_group(
            repositories,
            repository_id,
            HashSet::new(),
            |id| async move { Ok(Some(format!("hosted:{id}"))) },
            |id, _repo| async move { Ok(Some(format!("proxy:{id}"))) },
            not_found_error,
        )
        .await
    }

    #[tokio::test]
    async fn group_with_one_hosted_member_resolves_to_that_repository() {
        let org = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(group_id, org, vec![member_id]));
        store.insert(hosted_repo(member_id, org));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, group_id).await.unwrap();
        assert_eq!(result, Some(format!("hosted:{member_id}")));
    }

    /// Dependency-confusion regression: a proxy member listed before a hosted one must not shadow it.
    #[tokio::test]
    async fn a_proxy_member_listed_before_a_hosted_member_never_shadows_it() {
        let org = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let proxy_id = Uuid::new_v4();
        let hosted_id = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(group_id, org, vec![proxy_id, hosted_id]));
        store.insert(proxy_repo(proxy_id, org));
        store.insert(hosted_repo(hosted_id, org));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, group_id).await.unwrap();

        assert_eq!(result, Some(format!("hosted:{hosted_id}")), "the hosted member must win regardless of stored order");
    }

    #[tokio::test]
    async fn group_with_a_nested_group_resolves_two_levels_deep() {
        let org = Uuid::new_v4();
        let outer_group = Uuid::new_v4();
        let inner_group = Uuid::new_v4();
        let hosted_id = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(outer_group, org, vec![inner_group]));
        store.insert(group_repo(inner_group, org, vec![hosted_id]));
        store.insert(hosted_repo(hosted_id, org));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, outer_group).await.unwrap();
        assert_eq!(result, Some(format!("hosted:{hosted_id}")));
    }

    #[tokio::test]
    async fn group_that_contains_itself_is_caught_by_the_cycle_guard() {
        let org = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(group_id, org, vec![group_id]));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        // Caught by `visited` and yields "not found" (`None`), not infinite recursion.
        let result = resolve(&repositories, group_id).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn two_groups_referencing_each_other_are_caught_by_the_cycle_guard() {
        // The exact scenario resolve_in_group's own doc comment warns about.
        let org = Uuid::new_v4();
        let group_a = Uuid::new_v4();
        let group_b = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(group_a, org, vec![group_b]));
        store.insert(group_repo(group_b, org, vec![group_a]));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, group_a).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn empty_group_resolves_to_none_rather_than_an_error() {
        let org = Uuid::new_v4();
        let group_id = Uuid::new_v4();
        let store = FakeRepositories::new();
        store.insert(group_repo(group_id, org, vec![]));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, group_id).await;
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn missing_repository_surfaces_the_not_found_error() {
        let store = FakeRepositories::new();
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let err = resolve(&repositories, Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(DomainError::Infrastructure(_))), "got {err:?}");
    }

    /// Fails fast past `max_visits` lookups of the same id — turns a broken cycle guard into a clear error instead of a hang.
    struct VisitCountingRepositories {
        inner: FakeRepositories,
        visits: Mutex<HashMap<Uuid, usize>>,
        max_visits: usize,
    }

    impl VisitCountingRepositories {
        fn new(max_visits: usize) -> Self {
            Self { inner: FakeRepositories::new(), visits: Mutex::new(HashMap::new()), max_visits }
        }

        fn insert(&self, summary: PackageRepositorySummary) {
            self.inner.insert(summary);
        }
    }

    #[async_trait::async_trait]
    impl PackageRepositoryQueryPort for VisitCountingRepositories {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            let count = {
                let mut visits = self.visits.lock().unwrap();
                let count = visits.entry(id).or_insert(0);
                *count += 1;
                *count
            };
            if count > self.max_visits {
                return Err(EventStoreError::Storage(format!("repository {id} visited {count} times (max {}) - cycle guard not working", self.max_visits)));
            }
            self.inner.find_by_id(id).await
        }

        async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
            self.inner.find_by_org_and_name(organization_id, name).await
        }

        async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
            self.inner.list_all().await
        }
    }

    #[tokio::test]
    async fn cycle_guard_never_looks_up_the_same_repository_more_than_once() {
        let org = Uuid::new_v4();
        let group_a = Uuid::new_v4();
        let group_b = Uuid::new_v4();
        let store = VisitCountingRepositories::new(1);
        store.insert(group_repo(group_a, org, vec![group_b]));
        store.insert(group_repo(group_b, org, vec![group_a]));
        let repositories: Arc<dyn PackageRepositoryQueryPort> = Arc::new(store);

        let result = resolve(&repositories, group_a).await;
        assert_eq!(result.unwrap(), None);
    }
}
