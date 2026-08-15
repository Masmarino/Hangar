use std::sync::Arc;

use hangar_domain::audit::{DockerRegistryEvent, EventPublisherPort};
use hangar_domain::docker_registry::{Digest, DockerBlobStorePort, DockerImageName, DockerManifestRepositoryPort};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct DeleteManifestUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    blobs: Arc<dyn DockerBlobStorePort>,
    events: Arc<dyn EventPublisherPort>,
}

impl DeleteManifestUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>, blobs: Arc<dyn DockerBlobStorePort>, events: Arc<dyn EventPublisherPort>) -> Self {
        Self { manifests, blobs, events }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest, actor_id: Uuid) -> Result<(), ApplicationError> {
        let manifest = self
            .manifests
            .find_manifest_by_digest(repository_id, image_name, digest)
            .await?
            .ok_or(ApplicationError::DockerManifestNotFound)?;

        // Collected before the delete below: the join table this reads is only populated
        // while the manifest row still exists.
        let blob_digests_to_decrement = if manifest.media_type.is_index() {
            // A manifest list takes no blob references of its own; its members release
            // theirs only when deleted individually.
            Vec::new()
        } else {
            self.manifests.list_manifest_blob_digests(manifest.id).await?
        };

        // Deletes the manifest row first: its join rows cascade, which the blob-decrement
        // below needs — deleting the blob row while a join row still points at it is rejected.
        self.manifests.delete_manifest(repository_id, image_name, digest).await?;

        for blob_digest in blob_digests_to_decrement {
            self.blobs.decrement_ref_and_delete_if_zero(&blob_digest).await?;
        }

        self.events
            .publish_docker_event(
                DockerRegistryEvent::ManifestDeleted { image_name: image_name.as_str().to_string(), digest: digest.as_str().to_string() },
                repository_id,
                Some(actor_id),
            )
            .await?;

        Ok(())
    }
}

/// Deletes an entire image (every tag), rather than one tag/digest at a time.
pub struct DeleteDockerImageUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    delete_manifest: Arc<DeleteManifestUseCase>,
}

impl DeleteDockerImageUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>, delete_manifest: Arc<DeleteManifestUseCase>) -> Self {
        Self { manifests, delete_manifest }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName, actor_id: Uuid) -> Result<(), ApplicationError> {
        let digests = self.manifests.list_distinct_digests_for_image(repository_id, image_name).await?;
        for digest in digests {
            self.delete_manifest.execute(repository_id, image_name, &digest, actor_id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerBlobStore, FakeDockerEvents, FakeDockerManifestRepository};
    use hangar_domain::docker_registry::{DockerImageName, DockerManifest, DockerMediaType};

    async fn seed_manifest_with_one_blob(manifests: &FakeDockerManifestRepository, blobs: &FakeDockerBlobStore, repository_id: Uuid, name: &DockerImageName) -> (Digest, DockerManifest) {
        let blob_digest = Digest::of(b"layer-bytes");
        blobs.write(&blob_digest, b"layer-bytes").await.unwrap();
        blobs.increment_ref(&blob_digest).await.unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(), package_repository_id: repository_id, image_name: name.clone(),
            digest: Digest::of(b"manifest-bytes"), media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(), created_at: chrono::Utc::now(),
        };
        manifests.insert_manifest(&manifest, &[blob_digest.clone()]).await.unwrap();
        (blob_digest, manifest)
    }

    #[tokio::test]
    async fn deleting_a_manifest_decrements_and_removes_a_now_unreferenced_blob() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let (blob_digest, manifest) = seed_manifest_with_one_blob(&manifests, &blobs, repository_id, &name).await;

        let use_case = DeleteManifestUseCase::new(manifests.clone(), blobs.clone(), events);
        use_case.execute(repository_id, &name, &manifest.digest, Uuid::new_v4()).await.unwrap();

        assert!(!blobs.exists(&blob_digest).await.unwrap());
        assert!(manifests.find_manifest_by_digest(repository_id, &name, &manifest.digest).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_blob_shared_by_two_manifests_survives_deleting_only_one() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let (blob_digest, manifest_a) = seed_manifest_with_one_blob(&manifests, &blobs, repository_id, &name).await;
        // A second manifest referencing the SAME blob (as real images sharing a base layer would).
        blobs.increment_ref(&blob_digest).await.unwrap();
        let manifest_b = DockerManifest {
            id: Uuid::new_v4(), package_repository_id: repository_id, image_name: name.clone(),
            digest: Digest::of(b"other-manifest-bytes"), media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(), created_at: chrono::Utc::now(),
        };
        manifests.insert_manifest(&manifest_b, &[blob_digest.clone()]).await.unwrap();

        let use_case = DeleteManifestUseCase::new(manifests, blobs.clone(), events);
        use_case.execute(repository_id, &name, &manifest_a.digest, Uuid::new_v4()).await.unwrap();

        assert!(blobs.exists(&blob_digest).await.unwrap(), "blob is still referenced by manifest_b, must survive");
    }

    #[tokio::test]
    async fn deleting_a_whole_image_removes_every_tag_including_ones_sharing_a_digest() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let (_blob_a, manifest_a) = seed_manifest_with_one_blob(&manifests, &blobs, repository_id, &name).await;
        manifests.set_tag(repository_id, &name, "v1", manifest_a.id).await.unwrap();
        manifests.set_tag(repository_id, &name, "stable", manifest_a.id).await.unwrap();

        let other_blob = Digest::of(b"other-layer-bytes");
        blobs.write(&other_blob, b"other-layer-bytes").await.unwrap();
        let manifest_b = DockerManifest {
            id: Uuid::new_v4(), package_repository_id: repository_id, image_name: name.clone(),
            digest: Digest::of(b"other-manifest-bytes"), media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(), created_at: chrono::Utc::now(),
        };
        manifests.insert_manifest(&manifest_b, &[other_blob.clone()]).await.unwrap();
        manifests.set_tag(repository_id, &name, "v2", manifest_b.id).await.unwrap();

        let delete_manifest = Arc::new(DeleteManifestUseCase::new(manifests.clone(), blobs.clone(), events));
        let use_case = DeleteDockerImageUseCase::new(manifests.clone(), delete_manifest);
        use_case.execute(repository_id, &name, Uuid::new_v4()).await.unwrap();

        assert!(manifests.list_tags(repository_id, &name).await.unwrap().is_empty());
        assert!(manifests.find_manifest_by_digest(repository_id, &name, &manifest_a.digest).await.unwrap().is_none());
        assert!(manifests.find_manifest_by_digest(repository_id, &name, &manifest_b.digest).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_an_image_with_no_tags_at_all_is_a_no_op() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let events = Arc::new(FakeDockerEvents::new());
        let delete_manifest = Arc::new(DeleteManifestUseCase::new(manifests.clone(), blobs, events));
        let use_case = DeleteDockerImageUseCase::new(manifests, delete_manifest);

        use_case.execute(Uuid::new_v4(), &DockerImageName::parse("never-pushed").unwrap(), Uuid::new_v4()).await.unwrap();
    }
}
