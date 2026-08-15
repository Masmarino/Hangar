use std::collections::HashSet;
use std::sync::Arc;

use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerManifestRepositoryPort};
use hangar_domain::docker_remote::RemoteDockerRegistryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::group_resolve::resolve_in_group;

pub struct GetManifestUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    remote: Arc<dyn RemoteDockerRegistryPort>,
}

impl GetManifestUseCase {
    pub fn new(
        manifests: Arc<dyn DockerManifestRepositoryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        remote: Arc<dyn RemoteDockerRegistryPort>,
    ) -> Self {
        Self { manifests, repositories, remote }
    }

    /// `reference` is either a tag or a digest string — the Registry API v2 accepts both.
    pub async fn execute_hosted(&self, repository_id: Uuid, image_name: &DockerImageName, reference: &str) -> Result<Option<DockerManifest>, ApplicationError> {
        if let Ok(digest) = Digest::parse(reference) {
            return Ok(self.manifests.find_manifest_by_digest(repository_id, image_name, &digest).await?);
        }
        Ok(self.manifests.find_manifest_by_tag(repository_id, image_name, reference).await?)
    }

    pub fn execute<'a>(
        &'a self,
        repository_id: Uuid,
        image_name: &'a DockerImageName,
        reference: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<DockerManifest>, ApplicationError>> + Send + 'a>> {
        resolve_in_group(
            &self.repositories,
            repository_id,
            HashSet::new(),
            move |repository_id| self.execute_hosted(repository_id, image_name, reference),
            move |repository_id, repo| self.execute_proxy(repository_id, repo, image_name, reference),
            || ApplicationError::DockerManifestNotFound,
        )
    }

    async fn execute_proxy(&self, repository_id: Uuid, repo: PackageRepositorySummary, image_name: &DockerImageName, reference: &str) -> Result<Option<DockerManifest>, ApplicationError> {
        // A digest hit stays valid forever (content-addressed); a tag always re-fetches since it can move.
        if Digest::parse(reference).is_ok() {
            if let Some(cached) = self.execute_hosted(repository_id, image_name, reference).await? {
                return Ok(Some(cached));
            }
        }
        let remote_url = repo.remote_url.as_deref().ok_or_else(|| ApplicationError::InvalidDockerPayload("proxy repository has no remote_url configured".into()))?;
        // `None` means the remote genuinely 404'd — a real "not found", not an infra failure.
        let Some((bytes, content_type)) = self.remote.fetch_manifest(remote_url, image_name, reference, repo.remote_username.as_deref(), repo.remote_password.as_deref()).await? else {
            return Ok(None);
        };
        // Caching the fetched manifest locally is the route layer's job, not this use case's.
        Ok(Some(DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: image_name.clone(),
            digest: Digest::of(&bytes),
            // Trust the remote's Content-Type, or a manifest list gets misread as a single image.
            media_type: hangar_domain::docker_registry::DockerMediaType::parse(&content_type).unwrap_or(hangar_domain::docker_registry::DockerMediaType::DockerV2Manifest),
            body: bytes.clone(),
            created_at: chrono::Utc::now(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerManifestRepository, FakeRemoteDockerRegistry, FakeRepositories};
    use hangar_domain::docker_registry::{DockerImageName, DockerManifest, DockerMediaType};
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};

    #[tokio::test]
    async fn a_hosted_repository_serves_its_own_tagged_manifest() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: name.clone(),
            digest: Digest::of(b"manifest-bytes"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: chrono::Utc::now(),
        };
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", manifest.id).await.unwrap();

        let use_case = GetManifestUseCase::new(manifests, Arc::new(FakeRepositories::new()), Arc::new(FakeRemoteDockerRegistry::new()));
        let result = use_case.execute_hosted(repository_id, &name, "latest").await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn a_hosted_repository_without_the_tag_returns_none() {
        let use_case = GetManifestUseCase::new(
            Arc::new(FakeDockerManifestRepository::new()),
            Arc::new(FakeRepositories::new()),
            Arc::new(FakeRemoteDockerRegistry::new()),
        );
        let name = DockerImageName::parse("missing").unwrap();
        let result = use_case.execute_hosted(Uuid::new_v4(), &name, "latest").await.unwrap();
        assert!(result.is_none());
    }

    // `docker pull` probes references that legitimately 404 upstream (e.g. OCI referrers);
    // that must resolve to Ok(None), not Err, so the pull continues gracefully.
    #[tokio::test]
    async fn a_proxy_repositorys_remote_404_resolves_to_none_not_an_error() {
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(PackageRepositorySummary {
            id: repository_id,
            organization_id: Uuid::new_v4(),
            name: "proxy-repo".to_string(),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Proxy,
            remote_url: Some("https://registry-1.docker.io".to_string()),
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
        });
        let remote = Arc::new(FakeRemoteDockerRegistry::new());
        *remote.manifest_response.lock().unwrap() = None; // simulates the remote answering 404
        let use_case = GetManifestUseCase::new(Arc::new(FakeDockerManifestRepository::new()), repositories, remote);

        let name = DockerImageName::parse("library/alpine").unwrap();
        let result = use_case.execute(repository_id, &name, "sha256-deadbeef").await;

        assert!(matches!(result, Ok(None)), "expected Ok(None) for a remote 404, got {result:?}");
    }

    #[tokio::test]
    async fn a_cyclic_group_configuration_resolves_without_hanging() {
        let repo_a_id = Uuid::new_v4();
        let repo_b_id = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(PackageRepositorySummary {
            id: repo_a_id,
            organization_id: Uuid::new_v4(), name: "group-a".to_string(), format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Group, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_b_id],
        });
        repositories.insert(PackageRepositorySummary {
            id: repo_b_id,
            organization_id: Uuid::new_v4(), name: "group-b".to_string(), format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Group, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_a_id],
        });

        let use_case = GetManifestUseCase::new(Arc::new(FakeDockerManifestRepository::new()), repositories, Arc::new(FakeRemoteDockerRegistry::new()));
        let name = DockerImageName::parse("myimage").unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), use_case.execute(repo_a_id, &name, "latest"))
            .await
            .expect("execute() must not hang on a cyclic group configuration");
        assert!(result.unwrap().is_none());
    }
}
