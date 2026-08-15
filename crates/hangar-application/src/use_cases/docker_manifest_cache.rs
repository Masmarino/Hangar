use std::sync::Arc;

use hangar_domain::docker_registry::{DockerManifest, DockerManifestRepositoryPort};

use crate::error::ApplicationError;

pub struct CacheProxiedManifestUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl CacheProxiedManifestUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>) -> Self {
        Self { manifests }
    }

    /// No blob references or manifest-list-member rows are recorded. `ON CONFLICT DO NOTHING`
    /// in `insert_manifest` makes this safe to call concurrently for the same manifest.
    pub async fn execute(&self, manifest: &DockerManifest) -> Result<(), ApplicationError> {
        self.manifests.insert_manifest(manifest, &[]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::FakeDockerManifestRepository;
    use hangar_domain::docker_registry::{DockerImageName, DockerMediaType};
    use uuid::Uuid;

    fn sample_manifest(repository_id: Uuid, image_name: &DockerImageName) -> DockerManifest {
        DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: image_name.clone(),
            digest: hangar_domain::docker_registry::Digest::of(b"proxied-manifest-bytes"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn caches_a_proxy_fetched_manifest_findable_afterward_by_digest() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let use_case = CacheProxiedManifestUseCase::new(manifests.clone());
        let repository_id = Uuid::new_v4();
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);

        use_case.execute(&manifest).await.unwrap();

        assert!(manifests.find_manifest_by_digest(repository_id, &image_name, &manifest.digest).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn caching_the_same_manifest_twice_does_not_error() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let use_case = CacheProxiedManifestUseCase::new(manifests);
        let repository_id = Uuid::new_v4();
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);

        use_case.execute(&manifest).await.unwrap();
        use_case.execute(&manifest).await.unwrap();
    }
}
