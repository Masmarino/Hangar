use std::collections::HashSet;
use std::sync::Arc;

use hangar_domain::docker_registry::{DockerImageName, DockerManifestRepositoryPort};
use hangar_domain::package_repository::{PackageRepositoryQueryPort, RepositoryFormat};
use hangar_domain::permission::PermissionQueryPort;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct ListTagsUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl ListTagsUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>) -> Self {
        Self { manifests }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<String>, ApplicationError> {
        let mut tags = self.manifests.list_tags(repository_id, image_name).await?;
        tags.sort();
        Ok(tags)
    }
}

pub struct ListCatalogUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl ListCatalogUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>) -> Self {
        Self { manifests }
    }

    pub async fn execute(&self, repository_id: Uuid) -> Result<Vec<DockerImageName>, ApplicationError> {
        let names = self.manifests.list_repository_image_names(repository_id).await?;
        // Deduplicate image names defensively — callers must not assume the port returns unique names.
        let unique_names: HashSet<String> = names.into_iter().map(|n| n.as_str().to_string()).collect();
        let mut result: Vec<DockerImageName> = unique_names
            .into_iter()
            .map(|n| DockerImageName::parse(&n))
            .collect::<Result<Vec<_>, _>>()?;
        result.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(result)
    }
}

/// The `_catalog` endpoint's listing, across every readable Docker repository.
pub struct ListDockerRegistryCatalogUseCase {
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    permissions: Arc<dyn PermissionQueryPort>,
    manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl ListDockerRegistryCatalogUseCase {
    pub fn new(repositories: Arc<dyn PackageRepositoryQueryPort>, permissions: Arc<dyn PermissionQueryPort>, manifests: Arc<dyn DockerManifestRepositoryPort>) -> Self {
        Self { repositories, permissions, manifests }
    }

    /// Repository names are only unique per-organization, so without `organization_id` the
    /// catalog would leak cross-organization repository existence.
    pub async fn execute(&self, organization_id: Uuid, user_id: Uuid) -> Result<Vec<String>, ApplicationError> {
        let docker_repos: Vec<_> = self
            .repositories
            .list_all()
            .await?
            .into_iter()
            .filter(|r| r.format == RepositoryFormat::Docker && r.organization_id == organization_id)
            .collect();
        // One batched role lookup instead of one `find_role` per repository.
        let readable_repo_ids: std::collections::HashSet<Uuid> = self.permissions.list_for_user(user_id).await?.into_iter().map(|(id, _)| id).collect();
        let readable: Vec<_> = docker_repos.into_iter().filter(|r| readable_repo_ids.contains(&r.id)).collect();
        let readable_ids: Vec<Uuid> = readable.iter().map(|r| r.id).collect();

        let pairs = self.manifests.list_image_names_for_repositories(&readable_ids).await?;
        let repo_names: std::collections::HashMap<Uuid, &str> = readable.iter().map(|r| (r.id, r.name.as_str())).collect();
        let mut names: Vec<String> =
            pairs.into_iter().filter_map(|(repo_id, image_name)| repo_names.get(&repo_id).map(|name| format!("{name}/{}", image_name.as_str()))).collect();
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerManifestRepository, FakeRepositories};
    use async_trait::async_trait;
    use hangar_domain::docker_registry::{DockerImageName, DockerManifest, DockerMediaType, Digest};
    use hangar_domain::error::EventStoreError;
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryType};
    use hangar_domain::permission::Role;

    struct FakePermissions {
        entries: Vec<(Uuid, Uuid, Role)>,
        fail_list_for_user: bool,
    }

    impl FakePermissions {
        fn new(entries: Vec<(Uuid, Uuid, Role)>) -> Self {
            Self { entries, fail_list_for_user: false }
        }
    }

    #[async_trait]
    impl PermissionQueryPort for FakePermissions {
        async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError> {
            Ok(self.entries.iter().find(|(u, r, _)| *u == user_id && *r == repository_id).map(|(_, _, role)| *role))
        }
        async fn list_for_repository(&self, repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            Ok(self.entries.iter().filter(|(_, r, _)| *r == repository_id).map(|(u, _, role)| (*u, *role)).collect())
        }
        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError> {
            if self.fail_list_for_user {
                return Err(EventStoreError::Storage("simulated lookup failure".to_string()));
            }
            Ok(self.entries.iter().filter(|(u, _, _)| *u == user_id).map(|(_, r, role)| (*r, *role)).collect())
        }
        async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError> {
            unreachable!("not exercised by this use case's tests")
        }
        async fn count_all(&self) -> Result<usize, EventStoreError> {
            unreachable!("not exercised by this use case's tests")
        }
    }

    fn docker_repo(id: Uuid, organization_id: Uuid, name: &str) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id,
            name: name.to_string(),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes: None,
            retention_keep_last_n: None,
        }
    }

    fn manifest(repository_id: Uuid, name: &DockerImageName) -> DockerManifest {
        DockerManifest {
            id: Uuid::new_v4(), package_repository_id: repository_id, image_name: name.clone(),
            digest: Digest::of(name.as_str().as_bytes()), media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(), created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn lists_tags_for_one_image_sorted_and_ignores_other_images() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let other_name = DockerImageName::parse("other").unwrap();
        let m = manifest(repository_id, &name);
        manifests.insert_manifest(&m, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "v2", m.id).await.unwrap();
        manifests.set_tag(repository_id, &name, "v1", m.id).await.unwrap();
        let other = manifest(repository_id, &other_name);
        manifests.insert_manifest(&other, &[]).await.unwrap();
        manifests.set_tag(repository_id, &other_name, "latest", other.id).await.unwrap();

        let use_case = ListTagsUseCase::new(manifests);
        let tags = use_case.execute(repository_id, &name).await.unwrap();

        assert_eq!(tags, vec!["v1".to_string(), "v2".to_string()]);
    }

    #[tokio::test]
    async fn lists_catalog_image_names_sorted_and_deduplicated() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let m = manifest(repository_id, &name);
        manifests.insert_manifest(&m, &[]).await.unwrap();
        // Two tags on the SAME image must still surface it only once.
        manifests.set_tag(repository_id, &name, "v1", m.id).await.unwrap();
        manifests.set_tag(repository_id, &name, "v2", m.id).await.unwrap();

        let use_case = ListCatalogUseCase::new(manifests);
        let names = use_case.execute(repository_id).await.unwrap();

        assert_eq!(names, vec![name]);
    }

    #[tokio::test]
    async fn registry_catalog_excludes_a_readable_repository_from_a_different_organization() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let queried_org = Uuid::new_v4();
        let other_org = Uuid::new_v4();
        let in_queried_org = Uuid::new_v4();
        let in_other_org = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(docker_repo(in_queried_org, queried_org, "mine"));
        repositories.insert(docker_repo(in_other_org, other_org, "not-mine"));

        let name = DockerImageName::parse("myimage").unwrap();
        let mine_manifest = manifest(in_queried_org, &name);
        manifests.insert_manifest(&mine_manifest, &[]).await.unwrap();
        manifests.set_tag(in_queried_org, &name, "latest", mine_manifest.id).await.unwrap();
        let other_manifest = manifest(in_other_org, &name);
        manifests.insert_manifest(&other_manifest, &[]).await.unwrap();
        manifests.set_tag(in_other_org, &name, "latest", other_manifest.id).await.unwrap();

        let user_id = Uuid::new_v4();
        // Readable in BOTH repositories — proves the organization filter, not the
        // permission filter, is what excludes the other organization's repository.
        let permissions = Arc::new(FakePermissions::new(vec![(user_id, in_queried_org, Role::Read), (user_id, in_other_org, Role::Read)]));
        let use_case = ListDockerRegistryCatalogUseCase::new(repositories, permissions, manifests);

        let names = use_case.execute(queried_org, user_id).await.unwrap();

        assert_eq!(names, vec!["mine/myimage".to_string()]);
    }

    #[tokio::test]
    async fn registry_catalog_lists_only_repositories_the_caller_can_read() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let organization_id = Uuid::new_v4();
        let readable_id = Uuid::new_v4();
        let unreadable_id = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(docker_repo(readable_id, organization_id, "readable"));
        repositories.insert(docker_repo(unreadable_id, organization_id, "unreadable"));

        let name = DockerImageName::parse("myimage").unwrap();
        let readable_manifest = manifest(readable_id, &name);
        manifests.insert_manifest(&readable_manifest, &[]).await.unwrap();
        manifests.set_tag(readable_id, &name, "latest", readable_manifest.id).await.unwrap();
        let unreadable_manifest = manifest(unreadable_id, &name);
        manifests.insert_manifest(&unreadable_manifest, &[]).await.unwrap();
        manifests.set_tag(unreadable_id, &name, "latest", unreadable_manifest.id).await.unwrap();

        let user_id = Uuid::new_v4();
        let permissions = Arc::new(FakePermissions::new(vec![(user_id, readable_id, Role::Read)]));
        let use_case = ListDockerRegistryCatalogUseCase::new(repositories, permissions, manifests);

        let names = use_case.execute(organization_id, user_id).await.unwrap();

        assert_eq!(names, vec!["readable/myimage".to_string()]);
    }

    #[tokio::test]
    async fn registry_catalog_batches_multiple_readable_repositories_without_cross_contamination() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let organization_id = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(docker_repo(repo_a, organization_id, "alpha"));
        repositories.insert(docker_repo(repo_b, organization_id, "beta"));

        let name = DockerImageName::parse("myimage").unwrap();
        let manifest_a = manifest(repo_a, &name);
        manifests.insert_manifest(&manifest_a, &[]).await.unwrap();
        manifests.set_tag(repo_a, &name, "latest", manifest_a.id).await.unwrap();
        let manifest_b = manifest(repo_b, &name);
        manifests.insert_manifest(&manifest_b, &[]).await.unwrap();
        manifests.set_tag(repo_b, &name, "latest", manifest_b.id).await.unwrap();

        let user_id = Uuid::new_v4();
        let permissions = Arc::new(FakePermissions::new(vec![(user_id, repo_a, Role::Read), (user_id, repo_b, Role::Read)]));
        let use_case = ListDockerRegistryCatalogUseCase::new(repositories, permissions, manifests);

        let names = use_case.execute(organization_id, user_id).await.unwrap();

        assert_eq!(names, vec!["alpha/myimage".to_string(), "beta/myimage".to_string()], "the single batched query must attribute each image to its own repository");
    }

    #[tokio::test]
    async fn registry_catalog_is_empty_for_a_user_with_no_readable_repositories() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let organization_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(docker_repo(repository_id, organization_id, "some-repo"));
        let name = DockerImageName::parse("myimage").unwrap();
        let m = manifest(repository_id, &name);
        manifests.insert_manifest(&m, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", m.id).await.unwrap();

        let permissions = Arc::new(FakePermissions::new(vec![]));
        let use_case = ListDockerRegistryCatalogUseCase::new(repositories, permissions, manifests);

        assert!(use_case.execute(organization_id, Uuid::new_v4()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_failed_permission_lookup_surfaces_as_an_error_instead_of_a_silently_incomplete_catalog() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let organization_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(docker_repo(repository_id, organization_id, "repo"));

        let mut permissions = FakePermissions::new(vec![]);
        permissions.fail_list_for_user = true;
        let use_case = ListDockerRegistryCatalogUseCase::new(repositories, Arc::new(permissions), manifests);

        assert!(use_case.execute(organization_id, Uuid::new_v4()).await.is_err(), "a lookup failure must surface as an error, not an empty or partial catalog");
    }
}
