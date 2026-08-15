use std::collections::HashSet;
use std::sync::Arc;

use hangar_domain::docker_registry::{ByteStream, Digest, DockerBlobStorePort, DockerImageName, DockerManifestRepositoryPort};
use hangar_domain::error::DomainError;
use hangar_domain::docker_remote::RemoteDockerRegistryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::group_resolve::resolve_in_group;

pub struct GetBlobUseCase {
    blobs: Arc<dyn DockerBlobStorePort>,
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    remote: Arc<dyn RemoteDockerRegistryPort>,
}

impl GetBlobUseCase {
    pub fn new(blobs: Arc<dyn DockerBlobStorePort>, manifests: Arc<dyn DockerManifestRepositoryPort>, repositories: Arc<dyn PackageRepositoryQueryPort>, remote: Arc<dyn RemoteDockerRegistryPort>) -> Self {
        Self { blobs, manifests, repositories, remote }
    }

    pub fn execute<'a>(
        &'a self,
        repository_id: Uuid,
        image_name: &'a DockerImageName,
        digest: &'a Digest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, ApplicationError>> + Send + 'a>> {
        Box::pin(async move {
            resolve_in_group(
                &self.repositories,
                repository_id,
                HashSet::new(),
                // Blob storage is globally deduped, but a read must stay scoped to blobs this repository actually has, or any caller could read any repository's content by digest alone.
                move |repository_id| async move {
                    let reachable = self.manifests.blob_is_reachable(repository_id, digest).await?
                        || self.blobs.is_uploaded_to_repository(repository_id, digest).await?;
                    if reachable {
                        Ok(Some(self.blobs.read(digest).await?))
                    } else {
                        Ok(None)
                    }
                },
                move |repository_id, repo| self.execute_proxy(repository_id, repo, image_name, digest),
                || ApplicationError::DockerManifestNotFound,
            )
            .await
        })
    }

    /// Hot path for `docker push`'s per-layer `HEAD` check — local existence is answered by `size_if_exists` alone, no blob bytes read. Falls back to full `execute` only when not local.
    pub fn execute_exists<'a>(
        &'a self,
        repository_id: Uuid,
        image_name: &'a DockerImageName,
        digest: &'a Digest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<u64>, ApplicationError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(size_bytes) = self.blobs.size_if_exists(digest).await? {
                return Ok(Some(size_bytes));
            }
            Ok(self.execute(repository_id, image_name, digest).await?.map(|bytes| bytes.len() as u64))
        })
    }

    /// Same as `execute`, chunked instead of buffered whole for the common (local/cached) case. A proxy cache miss still fetches and verifies fully in memory first (`execute_proxy`).
    pub fn execute_stream<'a>(
        &'a self,
        repository_id: Uuid,
        image_name: &'a DockerImageName,
        digest: &'a Digest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<ByteStream>, ApplicationError>> + Send + 'a>> {
        Box::pin(async move {
            resolve_in_group(
                &self.repositories,
                repository_id,
                HashSet::new(),
                move |repository_id| async move {
                    let reachable = self.manifests.blob_is_reachable(repository_id, digest).await?
                        || self.blobs.is_uploaded_to_repository(repository_id, digest).await?;
                    if reachable {
                        Ok(Some(self.blobs.read_stream(digest).await?))
                    } else {
                        Ok(None)
                    }
                },
                move |repository_id, repo| async move {
                    let bytes = self.execute_proxy(repository_id, repo, image_name, digest).await?;
                    Ok(bytes.map(|b| Box::pin(futures::stream::once(async move { Ok::<_, DomainError>(bytes::Bytes::from(b)) })) as ByteStream))
                },
                || ApplicationError::DockerManifestNotFound,
            )
            .await
        })
    }

    async fn execute_proxy(&self, repository_id: Uuid, repo: PackageRepositorySummary, image_name: &DockerImageName, digest: &Digest) -> Result<Option<Vec<u8>>, ApplicationError> {
        let remote_url = repo
            .remote_url
            .as_deref()
            .ok_or_else(|| ApplicationError::InvalidDockerPayload("proxy repository has no remote_url configured".into()))?;
        // `None` means the remote genuinely 404'd — a real "not found", not an infra failure.
        let Some(bytes) = self.remote.fetch_blob(remote_url, image_name, digest, repo.remote_username.as_deref(), repo.remote_password.as_deref()).await? else {
            return Ok(None);
        };
        let computed = Digest::of(&bytes);
        if &computed != digest {
            return Err(ApplicationError::DockerDigestMismatch { expected: digest.as_str().to_string(), computed: computed.as_str().to_string() });
        }
        self.blobs.write(digest, &bytes).await?;
        self.blobs.link_to_repository(repository_id, &computed).await?;
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerBlobStore, FakeDockerManifestRepository, FakeRemoteDockerRegistry, FakeRepositories};
    use hangar_domain::docker_registry::{DockerImageName, DockerManifest, DockerMediaType};

    fn hosted_repo(id: Uuid) -> hangar_domain::package_repository::PackageRepositorySummary {
        hangar_domain::package_repository::PackageRepositorySummary {
            id,
            organization_id: Uuid::new_v4(), name: format!("repo-{id}"), format: hangar_domain::package_repository::RepositoryFormat::Docker,
            repo_type: hangar_domain::package_repository::RepositoryType::Hosted, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
        }
    }

    /// Links `digest` to a manifest actually stored in `repository_id`, the way a real push would — the fixture other tests need to make a blob reachable.
    async fn link_blob_to_repository(manifests: &FakeDockerManifestRepository, repository_id: Uuid, digest: &Digest) {
        let manifest = DockerManifest {
            id: Uuid::new_v4(), package_repository_id: repository_id, image_name: DockerImageName::parse("anything").unwrap(),
            digest: Digest::of(b"manifest-bytes"), media_type: DockerMediaType::DockerV2Manifest, body: b"{}".to_vec(), created_at: chrono::Utc::now(),
        };
        manifests.insert_manifest(&manifest, &[digest.clone()]).await.unwrap();
    }

    #[tokio::test]
    async fn a_blob_reachable_from_the_requested_repository_is_served() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let digest = Digest::of(b"layer-bytes");
        blobs.write(&digest, b"layer-bytes").await.unwrap();
        let repository_id = Uuid::new_v4();
        link_blob_to_repository(&manifests, repository_id, &digest).await;
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(hosted_repo(repository_id));

        let use_case = GetBlobUseCase::new(blobs, manifests, repositories, Arc::new(FakeRemoteDockerRegistry::new()));
        let bytes = use_case.execute(repository_id, &DockerImageName::parse("anything").unwrap(), &digest).await.unwrap();
        assert_eq!(bytes, Some(b"layer-bytes".to_vec()));
    }

    /// Blob storage is globally deduplicated by digest, but a repository the caller has no manifest in must not be able to serve content that only ever lived elsewhere.
    #[tokio::test]
    async fn a_blob_only_reachable_from_a_different_repository_is_not_served() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let digest = Digest::of(b"private-layer-bytes");
        blobs.write(&digest, b"private-layer-bytes").await.unwrap();
        let other_repository_id = Uuid::new_v4();
        link_blob_to_repository(&manifests, other_repository_id, &digest).await;

        let repositories = Arc::new(FakeRepositories::new());
        let requested_repository_id = Uuid::new_v4();
        repositories.insert(hosted_repo(requested_repository_id));
        let use_case = GetBlobUseCase::new(blobs, manifests, repositories, Arc::new(FakeRemoteDockerRegistry::new()));

        let result = use_case.execute(requested_repository_id, &DockerImageName::parse("anything").unwrap(), &digest).await.unwrap();
        assert!(result.is_none(), "a blob linked only to another repository must not be readable through this one");
    }

    #[tokio::test]
    async fn execute_stream_yields_the_same_bytes_as_execute_for_a_reachable_blob() {
        use futures::StreamExt;

        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let digest = Digest::of(b"streamed-layer-bytes");
        blobs.write(&digest, b"streamed-layer-bytes").await.unwrap();
        let repository_id = Uuid::new_v4();
        link_blob_to_repository(&manifests, repository_id, &digest).await;
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(hosted_repo(repository_id));

        let use_case = GetBlobUseCase::new(blobs, manifests, repositories, Arc::new(FakeRemoteDockerRegistry::new()));
        let mut stream = use_case.execute_stream(repository_id, &DockerImageName::parse("anything").unwrap(), &digest).await.unwrap().unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"streamed-layer-bytes");
    }

    #[tokio::test]
    async fn execute_stream_of_an_unreachable_blob_returns_none() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let digest = Digest::of(b"private-layer-bytes");
        blobs.write(&digest, b"private-layer-bytes").await.unwrap();
        let other_repository_id = Uuid::new_v4();
        link_blob_to_repository(&manifests, other_repository_id, &digest).await;

        let repositories = Arc::new(FakeRepositories::new());
        let requested_repository_id = Uuid::new_v4();
        repositories.insert(hosted_repo(requested_repository_id));
        let use_case = GetBlobUseCase::new(blobs, manifests, repositories, Arc::new(FakeRemoteDockerRegistry::new()));

        let result = use_case.execute_stream(requested_repository_id, &DockerImageName::parse("anything").unwrap(), &digest).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn a_missing_blob_against_a_hosted_repository_returns_none() {
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(hosted_repo(repository_id));
        let use_case = GetBlobUseCase::new(
            Arc::new(FakeDockerBlobStore::new()),
            Arc::new(FakeDockerManifestRepository::new()),
            repositories,
            Arc::new(FakeRemoteDockerRegistry::new()),
        );
        let result = use_case.execute(repository_id, &DockerImageName::parse("anything").unwrap(), &Digest::of(b"never-uploaded")).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn a_missing_blob_is_fetched_from_the_proxys_remote_registry() {
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repository_id,
            organization_id: Uuid::new_v4(), name: "proxy-repo".to_string(), format: hangar_domain::package_repository::RepositoryFormat::Docker,
            repo_type: hangar_domain::package_repository::RepositoryType::Proxy, remote_url: Some("https://registry-1.docker.io".to_string()), remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
        });
        let use_case = GetBlobUseCase::new(Arc::new(FakeDockerBlobStore::new()), Arc::new(FakeDockerManifestRepository::new()), repositories, Arc::new(FakeRemoteDockerRegistry::new()));

        // FakeRemoteDockerRegistry::fetch_blob always answers with these exact bytes.
        let digest = Digest::of(b"fake-blob-bytes");
        let result = use_case.execute(repository_id, &DockerImageName::parse("library/alpine").unwrap(), &digest).await.unwrap();
        assert_eq!(result, Some(b"fake-blob-bytes".to_vec()));
    }

    #[tokio::test]
    async fn a_cyclic_group_configuration_resolves_without_hanging() {
        let repo_a_id = Uuid::new_v4();
        let repo_b_id = Uuid::new_v4();
        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repo_a_id,
            organization_id: Uuid::new_v4(), name: "group-a".to_string(), format: hangar_domain::package_repository::RepositoryFormat::Docker,
            repo_type: hangar_domain::package_repository::RepositoryType::Group, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_b_id],
        });
        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repo_b_id,
            organization_id: Uuid::new_v4(), name: "group-b".to_string(), format: hangar_domain::package_repository::RepositoryFormat::Docker,
            repo_type: hangar_domain::package_repository::RepositoryType::Group, remote_url: None, remote_username: None, remote_password: None, quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_a_id],
        });

        let use_case = GetBlobUseCase::new(Arc::new(FakeDockerBlobStore::new()), Arc::new(FakeDockerManifestRepository::new()), repositories, Arc::new(FakeRemoteDockerRegistry::new()));
        let name = DockerImageName::parse("myimage").unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), use_case.execute(repo_a_id, &name, &Digest::of(b"never-uploaded")))
            .await
            .expect("execute() must not hang on a cyclic group configuration");
        assert!(result.unwrap().is_none());
    }
}
