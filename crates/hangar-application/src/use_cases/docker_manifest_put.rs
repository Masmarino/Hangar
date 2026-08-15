use std::sync::Arc;

use hangar_domain::audit::{DockerRegistryEvent, EventPublisherPort};
use hangar_domain::docker_registry::{Digest, DockerBlobStorePort, DockerImageName, DockerManifest, DockerManifestRepositoryPort, DockerMediaType};
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct PutManifestUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    blobs: Arc<dyn DockerBlobStorePort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    events: Arc<dyn EventPublisherPort>,
}

impl PutManifestUseCase {
    pub fn new(
        manifests: Arc<dyn DockerManifestRepositoryPort>,
        blobs: Arc<dyn DockerBlobStorePort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        events: Arc<dyn EventPublisherPort>,
    ) -> Self {
        Self { manifests, blobs, repositories, events }
    }

    /// The digest is computed from `raw_body`, never trusted from the client.
    pub async fn execute(
        &self,
        repository_id: Uuid,
        image_name: &DockerImageName,
        reference: &str,
        media_type: DockerMediaType,
        raw_body: &[u8],
        actor_id: Uuid,
    ) -> Result<Digest, ApplicationError> {
        let digest = Digest::of(raw_body);
        // Parsed only to extract digests below — the manifest stores raw_body verbatim, not this.
        let parsed: serde_json::Value =
            serde_json::from_slice(raw_body).map_err(|e| ApplicationError::InvalidDockerPayload(e.to_string()))?;

        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: image_name.clone(),
            digest: digest.clone(),
            media_type,
            body: raw_body.to_vec(),
            created_at: chrono::Utc::now(),
        };

        // `insert_manifest` returns the row's real id, which differs from `manifest.id` on conflict — every reference below must use this returned id.
        let manifest_id = if media_type.is_index() {
            let member_digests = extract_manifest_list_member_digests(&parsed)?;
            let (manifest_id, _) = self.manifests.insert_manifest(&manifest, &[]).await?;
            self.manifests.insert_manifest_list_members(manifest_id, &member_digests).await?;
            // No blob ref-counting here: members hold their own blob refs, released when they're deleted individually.
            manifest_id
        } else {
            let blob_digests = extract_blob_digests(&parsed)?;
            // Blobs are globally deduped, so existing isn't enough — must be reachable from THIS repository, or a pusher could mount another's private blob.
            for blob_digest in &blob_digests {
                let reachable = self.manifests.blob_is_reachable(repository_id, blob_digest).await?
                    || self.blobs.is_uploaded_to_repository(repository_id, blob_digest).await?;
                if !reachable {
                    return Err(ApplicationError::DockerBlobNotFound);
                }
            }

            // Quota is checked here, not at blob upload — a manifest push is what attributes bytes to a repository. Summing every referenced blob over-estimates on purpose.
            if let Some(repo) = self.repositories.find_by_id(repository_id).await? {
                if let Some(quota) = repo.quota_bytes {
                    let added_bytes = self.blobs.sum_sizes(&blob_digests).await?;
                    let used = self.blobs.used_bytes_for_repository(repository_id).await?;
                    if used + added_bytes > quota as u64 {
                        return Err(ApplicationError::StorageQuotaExceeded);
                    }
                }
            }

            let (manifest_id, inserted) = self.manifests.insert_manifest(&manifest, &blob_digests).await?;
            // Only bump refs on a real insert, or a re-push of identical content leaks one.
            if inserted {
                self.blobs.increment_ref_all(&blob_digests).await?;
            }
            manifest_id
        };

        // A digest reference (manifest-list members) is already reachable by digest — don't tag it.
        if Digest::parse(reference).is_err() {
            self.manifests.set_tag(repository_id, image_name, reference, manifest_id).await?;
        }

        self.events
            .publish_docker_event(
                DockerRegistryEvent::ImagePushed { image_name: image_name.as_str().to_string(), digest: digest.as_str().to_string() },
                repository_id,
                Some(actor_id),
            )
            .await?;

        Ok(digest)
    }
}

/// Extracts every blob digest a single-image manifest references: `config.digest` plus every entry in `layers[].digest`.
fn extract_blob_digests(body: &serde_json::Value) -> Result<Vec<Digest>, ApplicationError> {
    let mut digests = Vec::new();
    if let Some(config_digest) = body.get("config").and_then(|c| c.get("digest")).and_then(|d| d.as_str()) {
        digests.push(Digest::parse(config_digest).map_err(|e| ApplicationError::InvalidDockerPayload(e.to_string()))?);
    }
    if let Some(layers) = body.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(layer_digest) = layer.get("digest").and_then(|d| d.as_str()) {
                digests.push(Digest::parse(layer_digest).map_err(|e| ApplicationError::InvalidDockerPayload(e.to_string()))?);
            }
        }
    }
    Ok(digests)
}

/// Extracts every member manifest digest a manifest list / OCI index references (`manifests[].digest`).
fn extract_manifest_list_member_digests(body: &serde_json::Value) -> Result<Vec<Digest>, ApplicationError> {
    let mut digests = Vec::new();
    if let Some(manifests) = body.get("manifests").and_then(|m| m.as_array()) {
        for entry in manifests {
            if let Some(member_digest) = entry.get("digest").and_then(|d| d.as_str()) {
                digests.push(Digest::parse(member_digest).map_err(|e| ApplicationError::InvalidDockerPayload(e.to_string()))?);
            }
        }
    }
    Ok(digests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerBlobStore, FakeDockerEvents, FakeDockerManifestRepository, FakeRepositories};
    use hangar_domain::docker_registry::{Digest, DockerImageName};

    fn sample_manifest_body(blob_digest: &str) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": { "digest": blob_digest, "size": 100 },
            "layers": []
        })
    }

    #[tokio::test]
    async fn pushing_a_manifest_stores_it_and_tags_it_and_increments_blob_refs() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let config_digest = Digest::of(b"config-bytes");
        blobs.write(&config_digest, b"config-bytes").await.unwrap();
        blobs.link_to_repository(repository_id, &config_digest).await.unwrap();

        let use_case = PutManifestUseCase::new(manifests.clone(), blobs.clone(), Arc::new(FakeRepositories::new()), events);
        let body = sample_manifest_body(config_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let media_type = DockerMediaType::DockerV2Manifest;

        use_case.execute(repository_id, &name, "latest", media_type, &body_bytes, Uuid::new_v4()).await.unwrap();

        let tagged = manifests.find_manifest_by_tag(repository_id, &name, "latest").await.unwrap();
        assert!(tagged.is_some());
        assert!(matches!(blobs.blobs.lock().unwrap().get(config_digest.as_str()), Some((_, 1))));
    }

    #[tokio::test]
    async fn pushing_a_second_tag_of_byte_identical_content_tags_both() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let config_digest = Digest::of(b"config-bytes");
        blobs.write(&config_digest, b"config-bytes").await.unwrap();
        blobs.link_to_repository(repository_id, &config_digest).await.unwrap();

        let use_case = PutManifestUseCase::new(manifests.clone(), blobs.clone(), Arc::new(FakeRepositories::new()), events);
        let body = sample_manifest_body(config_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let media_type = DockerMediaType::DockerV2Manifest;

        use_case.execute(repository_id, &name, "latest", media_type, &body_bytes, Uuid::new_v4()).await.unwrap();
        use_case.execute(repository_id, &name, "v2", media_type, &body_bytes, Uuid::new_v4()).await.unwrap();

        let latest = manifests.find_manifest_by_tag(repository_id, &name, "latest").await.unwrap();
        let v2 = manifests.find_manifest_by_tag(repository_id, &name, "v2").await.unwrap();
        assert!(latest.is_some());
        assert!(v2.is_some());
        assert_eq!(latest.unwrap().id, v2.unwrap().id, "both tags must resolve to the SAME persisted manifest row");
        assert!(
            matches!(blobs.blobs.lock().unwrap().get(config_digest.as_str()), Some((_, 1))),
            "re-pushing byte-identical content must not bump the ref count again — the blob rows already exist from the first push"
        );
    }

    #[tokio::test]
    async fn pushing_by_digest_reference_does_not_create_a_tag() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let config_digest = Digest::of(b"config-bytes");
        blobs.write(&config_digest, b"config-bytes").await.unwrap();
        blobs.link_to_repository(repository_id, &config_digest).await.unwrap();
        let use_case = PutManifestUseCase::new(manifests.clone(), blobs, Arc::new(FakeRepositories::new()), events);
        let body = sample_manifest_body(config_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let manifest_digest = Digest::of(&body_bytes);

        use_case.execute(repository_id, &name, manifest_digest.as_str(), DockerMediaType::DockerV2Manifest, &body_bytes, Uuid::new_v4()).await.unwrap();

        assert_eq!(manifests.list_tags(repository_id, &name).await.unwrap(), Vec::<String>::new());
        assert!(manifests.find_manifest_by_digest(repository_id, &name, &manifest_digest).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn pushing_a_manifest_referencing_an_unknown_blob_is_rejected() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let use_case = PutManifestUseCase::new(manifests, blobs, Arc::new(FakeRepositories::new()), events);
        let name = DockerImageName::parse("myimage").unwrap();
        let missing_digest = Digest::of(b"never-uploaded");
        let body = sample_manifest_body(missing_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let result = use_case.execute(Uuid::new_v4(), &name, "latest", DockerMediaType::DockerV2Manifest, &body_bytes, Uuid::new_v4()).await;
        assert!(matches!(result, Err(ApplicationError::DockerBlobNotFound)));
    }

    #[tokio::test]
    async fn pushing_a_manifest_referencing_a_blob_that_exists_globally_but_belongs_to_a_different_repository_is_rejected() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let victim_repository_id = Uuid::new_v4();
        let attacker_repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let victim_digest = Digest::of(b"victims-private-layer");
        blobs.write(&victim_digest, b"victims-private-layer").await.unwrap();
        blobs.link_to_repository(victim_repository_id, &victim_digest).await.unwrap();

        let use_case = PutManifestUseCase::new(manifests, blobs, Arc::new(FakeRepositories::new()), events);
        let body = sample_manifest_body(victim_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let result = use_case.execute(attacker_repository_id, &name, "latest", DockerMediaType::DockerV2Manifest, &body_bytes, Uuid::new_v4()).await;

        assert!(matches!(result, Err(ApplicationError::DockerBlobNotFound)), "got {result:?}");
    }

    fn repo_with_quota(id: Uuid, quota_bytes: Option<i64>) -> hangar_domain::package_repository::PackageRepositorySummary {
        hangar_domain::package_repository::PackageRepositorySummary {
            id,
            organization_id: Uuid::new_v4(),
            name: "myrepo".to_string(),
            format: hangar_domain::package_repository::RepositoryFormat::Docker,
            repo_type: hangar_domain::package_repository::RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes,
            retention_keep_last_n: None,
        }
    }

    #[tokio::test]
    async fn pushing_a_manifest_whose_blobs_exceed_the_quota_is_rejected() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let config_digest = Digest::of(b"config-bytes"); // 12 bytes
        blobs.write(&config_digest, b"config-bytes").await.unwrap();
        blobs.link_to_repository(repository_id, &config_digest).await.unwrap();
        repositories.insert(repo_with_quota(repository_id, Some(5)));

        let use_case = PutManifestUseCase::new(manifests, blobs, repositories, events);
        let body = sample_manifest_body(config_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let result = use_case.execute(repository_id, &name, "latest", DockerMediaType::DockerV2Manifest, &body_bytes, Uuid::new_v4()).await;

        assert!(matches!(result, Err(ApplicationError::StorageQuotaExceeded)), "got {result:?}");
    }

    #[tokio::test]
    async fn pushing_a_manifest_within_the_quota_succeeds() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        let config_digest = Digest::of(b"config-bytes");
        blobs.write(&config_digest, b"config-bytes").await.unwrap();
        blobs.link_to_repository(repository_id, &config_digest).await.unwrap();
        repositories.insert(repo_with_quota(repository_id, Some(1024)));

        let use_case = PutManifestUseCase::new(manifests, blobs, repositories, events);
        let body = sample_manifest_body(config_digest.as_str());
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let result = use_case.execute(repository_id, &name, "latest", DockerMediaType::DockerV2Manifest, &body_bytes, Uuid::new_v4()).await;

        assert!(result.is_ok(), "got {result:?}");
    }

    #[tokio::test]
    async fn pushing_a_manifest_list_index_is_never_quota_checked() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let events = Arc::new(FakeDockerEvents::new());
        let repositories = Arc::new(FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("myimage").unwrap();
        repositories.insert(repo_with_quota(repository_id, Some(1)));

        let use_case = PutManifestUseCase::new(manifests, blobs, repositories, events);
        let member_digest = Digest::of(b"member-manifest-bytes");
        let index_body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{ "digest": member_digest.as_str(), "size": 100, "platform": { "architecture": "amd64", "os": "linux" } }]
        });
        let body_bytes = serde_json::to_vec(&index_body).unwrap();

        let result =
            use_case.execute(repository_id, &name, "latest", DockerMediaType::OciIndex, &body_bytes, Uuid::new_v4()).await;

        assert!(result.is_ok(), "got {result:?}");
    }
}
