use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifestRepositoryPort};
use hangar_domain::npm_package::NpmPackageRepositoryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, RepositoryFormat};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::docker_manifest_delete::DeleteManifestUseCase;
use crate::use_cases::npm_unpublish::UnpublishNpmPackageUseCase;

/// Nil UUID: never a real user's id, so always distinguishable from a human-triggered deletion.
pub const RETENTION_SWEEP_ACTOR: Uuid = Uuid::nil();

/// Never deleted regardless of rank — `docker pull image` with no explicit tag resolves to this.
const PROTECTED_DOCKER_TAG: &str = "latest";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionSweepReport {
    pub npm_versions_deleted: usize,
    pub docker_tags_deleted: usize,
}

/// Run periodically by a background timer, not on any request path. Deletes via `UnpublishNpmPackageUseCase`/`DeleteManifestUseCase` to reuse their storage/audit side effects.
pub struct SweepRetentionUseCase {
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    npm_packages: Arc<dyn NpmPackageRepositoryPort>,
    unpublish_npm: Arc<UnpublishNpmPackageUseCase>,
    docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
    delete_docker_manifest: Arc<DeleteManifestUseCase>,
}

impl SweepRetentionUseCase {
    pub fn new(
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        npm_packages: Arc<dyn NpmPackageRepositoryPort>,
        unpublish_npm: Arc<UnpublishNpmPackageUseCase>,
        docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
        delete_docker_manifest: Arc<DeleteManifestUseCase>,
    ) -> Self {
        Self { repositories, npm_packages, unpublish_npm, docker_manifests, delete_docker_manifest }
    }

    pub async fn execute(&self) -> Result<RetentionSweepReport, ApplicationError> {
        let mut report = RetentionSweepReport::default();
        for repo in self.repositories.list_all().await? {
            let Some(keep_n) = repo.retention_keep_last_n else { continue };
            let keep_n = keep_n.max(0) as usize;
            match repo.format {
                RepositoryFormat::Npm => self.sweep_npm(repo.id, keep_n, &mut report).await?,
                RepositoryFormat::Docker => self.sweep_docker(repo.id, keep_n, &mut report).await?,
            }
        }
        Ok(report)
    }

    /// Newest-first, keeps everything within `keep_n` plus any version a dist-tag still points at — a sweep must never silently break `npm install @latest`.
    async fn sweep_npm(&self, repository_id: Uuid, keep_n: usize, report: &mut RetentionSweepReport) -> Result<(), ApplicationError> {
        let packages = self.npm_packages.search(repository_id, "", i64::MAX).await?;
        let package_ids: Vec<Uuid> = packages.iter().map(|p| p.id).collect();
        let mut versions_by_package: std::collections::HashMap<Uuid, Vec<_>> = std::collections::HashMap::new();
        for version in self.npm_packages.list_versions_for_packages(&package_ids).await? {
            versions_by_package.entry(version.npm_package_id).or_default().push(version);
        }
        let mut dist_tags_by_package: std::collections::HashMap<Uuid, HashSet<String>> = std::collections::HashMap::new();
        for tag in self.npm_packages.list_dist_tags_for_packages(&package_ids).await? {
            dist_tags_by_package.entry(tag.npm_package_id).or_default().insert(tag.version.as_str());
        }

        for package in packages {
            let mut versions = versions_by_package.remove(&package.id).unwrap_or_default();
            if versions.len() <= keep_n {
                continue;
            }
            let protected = dist_tags_by_package.remove(&package.id).unwrap_or_default();
            versions.sort_by_key(|v| std::cmp::Reverse(v.published_at));
            for (rank, version) in versions.iter().enumerate() {
                if rank < keep_n || protected.contains(&version.version.as_str()) {
                    continue;
                }
                // Errors are swallowed: one package's stale state must not abort the whole sweep.
                if self.unpublish_npm.execute_version(repository_id, &package.name, &version.version, RETENTION_SWEEP_ACTOR).await.is_ok() {
                    report.npm_versions_deleted += 1;
                }
            }
        }
        Ok(())
    }

    /// Ranks tags by `DockerManifest::created_at` (when the digest was first pushed) and deletes everything past `keep_n`, except `latest`.
    async fn sweep_docker(&self, repository_id: Uuid, keep_n: usize, report: &mut RetentionSweepReport) -> Result<(), ApplicationError> {
        let mut summaries_by_image: std::collections::HashMap<DockerImageName, Vec<(String, Digest, DateTime<Utc>)>> = std::collections::HashMap::new();
        for (image_name, tag, digest, _media_type, created_at) in self.docker_manifests.list_repository_tag_manifest_summaries(repository_id).await? {
            summaries_by_image.entry(image_name).or_default().push((tag, digest, created_at));
        }

        for (image_name, summaries) in summaries_by_image {
            if summaries.len() <= keep_n {
                continue;
            }

            let mut dated_tags: Vec<_> = summaries.into_iter().map(|(tag, digest, created_at)| (tag, created_at, digest)).collect();
            dated_tags.sort_by_key(|(_, created_at, _)| std::cmp::Reverse(*created_at));

            // A digest is protected if ANY of its tags is — deleting by digest removes every tag sharing it, so one kept alias must not doom the rest.
            let mut protected_digests = HashSet::new();
            for (rank, (tag, _created_at, digest)) in dated_tags.iter().enumerate() {
                if rank < keep_n || tag == PROTECTED_DOCKER_TAG {
                    protected_digests.insert(digest.clone());
                }
            }

            let mut deleted_digests = HashSet::new();
            for (_tag, _created_at, digest) in &dated_tags {
                if protected_digests.contains(digest) || deleted_digests.contains(digest) {
                    continue;
                }
                if self.delete_docker_manifest.execute(repository_id, &image_name, digest, RETENTION_SWEEP_ACTOR).await.is_ok() {
                    report.docker_tags_deleted += 1;
                    deleted_digests.insert(digest.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerBlobStore, FakeDockerEvents, FakeDockerManifestRepository, FakeRepositories as FakeDockerRepositories};
    use crate::use_cases::npm_test_support::{FakeEvents, FakePackages, FakeRepositories as FakeNpmRepositories, FakeStorage};
    use chrono::{Duration, Utc};
    use hangar_domain::docker_registry::{Digest, DockerManifest, DockerMediaType};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryType};
    use hangar_domain::storage::StorageBackendPort;

    fn npm_repo(id: Uuid, keep_last_n: Option<i32>) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id: Uuid::new_v4(),
            name: "npm-repo".to_string(),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes: None,
            retention_keep_last_n: keep_last_n,
        }
    }

    fn docker_repo(id: Uuid, keep_last_n: Option<i32>) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id,
            organization_id: Uuid::new_v4(),
            name: "docker-repo".to_string(),
            format: RepositoryFormat::Docker,
            repo_type: RepositoryType::Hosted,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: vec![],
            quota_bytes: None,
            retention_keep_last_n: keep_last_n,
        }
    }

    async fn seed_npm_version(packages: &FakePackages, storage: &FakeStorage, repository_id: Uuid, package_id: Uuid, version_str: &str, published_at: chrono::DateTime<Utc>) {
        let version = NpmVersion::parse(version_str).unwrap();
        let storage_key = format!("pkg/-/pkg-{version_str}.tgz");
        storage.write(repository_id, &storage_key, b"bytes").await.unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package_id,
                version,
                manifest: serde_json::json!({}),
                shasum: "s".into(),
                integrity: "i".into(),
                tarball_storage_key: storage_key,
                tarball_size_bytes: 5,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at,
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
    }

    fn use_case_with(
        repositories: Arc<dyn hangar_domain::package_repository::PackageRepositoryQueryPort>,
        packages: Arc<FakePackages>,
        storage: Arc<FakeStorage>,
        manifests: Arc<FakeDockerManifestRepository>,
        blobs: Arc<FakeDockerBlobStore>,
    ) -> SweepRetentionUseCase {
        let events = Arc::new(FakeEvents::new());
        let unpublish = Arc::new(UnpublishNpmPackageUseCase::new(packages.clone(), storage.clone(), events));
        let docker_events = Arc::new(FakeDockerEvents::new());
        let delete_manifest = Arc::new(DeleteManifestUseCase::new(manifests.clone(), blobs, docker_events));
        SweepRetentionUseCase::new(repositories, packages, unpublish, manifests, delete_manifest)
    }

    #[tokio::test]
    async fn prunes_npm_versions_beyond_the_keep_count_oldest_first() {
        let repositories = Arc::new(FakeNpmRepositories::new());
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(npm_repo(repository_id, Some(2)));

        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        packages.create_package(&package).await.unwrap();
        let now = Utc::now();
        seed_npm_version(&packages, &storage, repository_id, package.id, "1.0.0", now - Duration::days(3)).await;
        seed_npm_version(&packages, &storage, repository_id, package.id, "1.1.0", now - Duration::days(2)).await;
        seed_npm_version(&packages, &storage, repository_id, package.id, "1.2.0", now - Duration::days(1)).await;
        seed_npm_version(&packages, &storage, repository_id, package.id, "1.3.0", now).await;

        let use_case = use_case_with(repositories, packages.clone(), storage, Arc::new(FakeDockerManifestRepository::new()), Arc::new(FakeDockerBlobStore::new()));
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.npm_versions_deleted, 2);
        let remaining = packages.list_versions(package.id).await.unwrap();
        let remaining_versions: Vec<String> = remaining.iter().map(|v| v.version.as_str()).collect();
        assert!(remaining_versions.contains(&"1.3.0".to_string()));
        assert!(remaining_versions.contains(&"1.2.0".to_string()));
        assert!(!remaining_versions.contains(&"1.0.0".to_string()));
        assert!(!remaining_versions.contains(&"1.1.0".to_string()));
    }

    #[tokio::test]
    async fn a_dist_tagged_old_version_is_never_pruned() {
        let repositories = Arc::new(FakeNpmRepositories::new());
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(npm_repo(repository_id, Some(1)));

        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        packages.create_package(&package).await.unwrap();
        let now = Utc::now();
        seed_npm_version(&packages, &storage, repository_id, package.id, "1.0.0", now - Duration::days(2)).await;
        seed_npm_version(&packages, &storage, repository_id, package.id, "2.0.0", now).await;
        // An old version deliberately still tagged (e.g. a maintained LTS line) must survive even though rank alone would prune it.
        packages.set_dist_tag(package.id, "lts", &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        let use_case = use_case_with(repositories, packages.clone(), storage, Arc::new(FakeDockerManifestRepository::new()), Arc::new(FakeDockerBlobStore::new()));
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.npm_versions_deleted, 0);
        let remaining: Vec<String> = packages.list_versions(package.id).await.unwrap().iter().map(|v| v.version.as_str()).collect();
        assert!(remaining.contains(&"1.0.0".to_string()));
    }

    #[tokio::test]
    async fn a_repository_without_a_policy_is_left_untouched() {
        let repositories = Arc::new(FakeNpmRepositories::new());
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(npm_repo(repository_id, None));

        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        packages.create_package(&package).await.unwrap();
        let now = Utc::now();
        for i in 0..5 {
            seed_npm_version(&packages, &storage, repository_id, package.id, &format!("1.{i}.0"), now - Duration::days(i)).await;
        }

        let use_case = use_case_with(repositories, packages.clone(), storage, Arc::new(FakeDockerManifestRepository::new()), Arc::new(FakeDockerBlobStore::new()));
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.npm_versions_deleted, 0);
        assert_eq!(packages.list_versions(package.id).await.unwrap().len(), 5);
    }

    fn docker_manifest(repository_id: Uuid, name: &hangar_domain::docker_registry::DockerImageName, content: &[u8], created_at: chrono::DateTime<Utc>) -> DockerManifest {
        DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: name.clone(),
            digest: Digest::of(content),
            media_type: DockerMediaType::DockerV2Manifest,
            body: content.to_vec(),
            created_at,
        }
    }

    #[tokio::test]
    async fn prunes_docker_tags_beyond_the_keep_count_but_never_latest() {
        let repositories = Arc::new(FakeDockerRepositories::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(docker_repo(repository_id, Some(1)));
        let image_name = hangar_domain::docker_registry::DockerImageName::parse("my-app").unwrap();
        let now = Utc::now();

        let v1 = docker_manifest(repository_id, &image_name, b"v1", now - Duration::days(2));
        let v2 = docker_manifest(repository_id, &image_name, b"v2", now - Duration::days(1));
        let latest = docker_manifest(repository_id, &image_name, b"latest-content", now - Duration::days(3));
        manifests.insert_manifest(&v1, &[]).await.unwrap();
        manifests.insert_manifest(&v2, &[]).await.unwrap();
        manifests.insert_manifest(&latest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "1.0.0", v1.id).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "1.1.0", v2.id).await.unwrap();
        // Oldest of all by created_at, but protected by name.
        manifests.set_tag(repository_id, &image_name, "latest", latest.id).await.unwrap();

        let use_case = use_case_with(
            repositories,
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            manifests.clone(),
            Arc::new(FakeDockerBlobStore::new()),
        );
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.docker_tags_deleted, 1);
        let remaining_tags = manifests.list_tags(repository_id, &image_name).await.unwrap();
        assert!(remaining_tags.contains(&"1.1.0".to_string()), "the newest non-latest tag must survive");
        assert!(remaining_tags.contains(&"latest".to_string()), "latest must never be pruned");
        assert!(!remaining_tags.contains(&"1.0.0".to_string()), "the oldest non-latest tag must be pruned");
    }

    #[tokio::test]
    async fn a_kept_tag_survives_even_when_a_pruned_tag_shares_its_digest() {
        let repositories = Arc::new(FakeDockerRepositories::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(docker_repo(repository_id, Some(1)));
        let image_name = hangar_domain::docker_registry::DockerImageName::parse("my-app").unwrap();
        let now = Utc::now();

        // "v3" and "stable" share a digest (common in CI/CD); "v2" is separate and older.
        let shared_build = docker_manifest(repository_id, &image_name, b"shared-build", now);
        let v2 = docker_manifest(repository_id, &image_name, b"v2", now - Duration::days(1));
        manifests.insert_manifest(&shared_build, &[]).await.unwrap();
        manifests.insert_manifest(&v2, &[]).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "v3", shared_build.id).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "stable", shared_build.id).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "v2", v2.id).await.unwrap();

        let use_case = use_case_with(
            repositories,
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            manifests.clone(),
            Arc::new(FakeDockerBlobStore::new()),
        );
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.docker_tags_deleted, 1, "only the v2 digest should have been deleted");
        let remaining_tags = manifests.list_tags(repository_id, &image_name).await.unwrap();
        assert!(remaining_tags.contains(&"v3".to_string()), "v3 must survive: it shares a digest with a kept tag");
        assert!(remaining_tags.contains(&"stable".to_string()), "stable must survive: it shares a digest with a kept tag");
        assert!(!remaining_tags.contains(&"v2".to_string()), "v2 has its own, older digest and must be pruned");
    }

    #[tokio::test]
    async fn a_docker_repository_within_the_keep_count_is_untouched() {
        let repositories = Arc::new(FakeDockerRepositories::new());
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(docker_repo(repository_id, Some(5)));
        let image_name = hangar_domain::docker_registry::DockerImageName::parse("my-app").unwrap();
        let now = Utc::now();
        let manifest = docker_manifest(repository_id, &image_name, b"only-tag", now);
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &image_name, "1.0.0", manifest.id).await.unwrap();

        let use_case = use_case_with(
            repositories,
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            manifests.clone(),
            Arc::new(FakeDockerBlobStore::new()),
        );
        let report = use_case.execute().await.unwrap();

        assert_eq!(report.docker_tags_deleted, 0);
        assert_eq!(manifests.list_tags(repository_id, &image_name).await.unwrap(), vec!["1.0.0".to_string()]);
    }
}
