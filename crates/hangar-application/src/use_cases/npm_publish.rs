use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use hangar_domain::audit::{EventPublisherPort, NpmPackageEvent};
use hangar_domain::npm_package::{
    NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageRepositoryPort, NpmPackageVersion, NpmVersion,
};
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use hangar_domain::storage::StorageBackendPort;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha512;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct PublishNpmPackageUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    storage: Arc<dyn StorageBackendPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    events: Arc<dyn EventPublisherPort>,
}

impl PublishNpmPackageUseCase {
    pub fn new(
        packages: Arc<dyn NpmPackageRepositoryPort>,
        storage: Arc<dyn StorageBackendPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        events: Arc<dyn EventPublisherPort>,
    ) -> Self {
        Self { packages, storage, repositories, events }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        version: &NpmVersion,
        manifest: serde_json::Value,
        tarball_bytes: Bytes,
        publisher_id: Uuid,
    ) -> Result<Uuid, ApplicationError> {
        let package = match self.packages.find_package(repository_id, name).await? {
            Some(existing) => existing,
            None => {
                let created = NpmPackage {
                    id: Uuid::new_v4(),
                    package_repository_id: repository_id,
                    name: name.clone(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    metadata_fetched_at: None,
                    cached_metadata: None,
                };
                self.packages.create_package(&created).await?;
                created
            }
        };

        if self.packages.find_version(package.id, version).await?.is_some() {
            return Err(ApplicationError::PackageVersionExists);
        }

        if let Some(repo) = self.repositories.find_by_id(repository_id).await? {
            if let Some(quota) = repo.quota_bytes {
                let used = self.storage.used_bytes(repository_id).await?;
                if used + tarball_bytes.len() as u64 > quota as u64 {
                    return Err(ApplicationError::StorageQuotaExceeded);
                }
            }
        }

        // Hashing a full tarball is CPU-bound; off the async executor so a large publish doesn't stall other requests.
        // `Bytes::clone()` is a refcount bump (O(1)), not a copy — unlike the `Vec<u8>` this used to be built from.
        let tarball_for_hashing = tarball_bytes.clone();
        let (shasum, integrity) = tokio::task::spawn_blocking(move || {
            let shasum = hex::encode(Sha1::digest(&tarball_for_hashing));
            let integrity = format!("sha512-{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, Sha512::digest(&tarball_for_hashing)));
            (shasum, integrity)
        })
        .await
        .map_err(|e| hangar_domain::error::DomainError::Infrastructure(e.to_string()))?;

        // Derived server-side, not from the client's attachment filename, or a crafted
        // filename could overwrite another version's tarball.
        let safe_scope_and_name = name.as_str().trim_start_matches('@');
        let tarball_name = format!("{}-{}.tgz", name.local_name(), version.as_str());
        let storage_key = format!("{safe_scope_and_name}/-/{tarball_name}");
        self.storage.write(repository_id, &storage_key, &tarball_bytes).await?;

        let npm_version = NpmPackageVersion {
            id: Uuid::new_v4(),
            npm_package_id: package.id,
            version: version.clone(),
            manifest,
            shasum,
            integrity,
            tarball_storage_key: storage_key,
            tarball_size_bytes: tarball_bytes.len() as i64,
            deprecated: false,
            deprecated_message: None,
            published_by: Some(publisher_id),
            published_at: Utc::now(),
            origin: NpmPackageOrigin::Local,
        };
        self.packages.insert_version(&npm_version).await?;

        // npm convention: publishing a prerelease version (has a `-` suffix,
        // e.g. 1.0.0-beta.1) never moves the `latest` dist-tag automatically.
        if version.as_str().find('-').is_none() {
            self.packages.set_dist_tag(package.id, "latest", version).await?;
        }

        self.events
            .publish_npm_event(
                NpmPackageEvent::PackagePushed { package_name: name.as_str().to_string(), version: version.as_str() },
                package.id,
                Some(publisher_id),
            )
            .await?;

        Ok(npm_version.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeEvents, FakePackages, FakeRepositories, FakeStorage};
    use hangar_domain::npm_package::{NpmPackageName, NpmVersion};

    fn use_case() -> PublishNpmPackageUseCase {
        PublishNpmPackageUseCase::new(
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            Arc::new(FakeRepositories::new()),
            Arc::new(FakeEvents::new()),
        )
    }

    #[tokio::test]
    async fn publishing_a_new_package_creates_it_and_sets_latest() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let use_case = PublishNpmPackageUseCase::new(packages.clone(), storage.clone(), Arc::new(FakeRepositories::new()), events.clone());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"tarball-bytes"), Uuid::new_v4()).await.unwrap();

        let package = packages.packages.lock().unwrap().get(&(repository_id, name.as_str().to_string())).cloned().expect("package should have been created");
        let latest = packages.dist_tags.lock().unwrap().get(&(package.id, "latest".to_string())).cloned();
        assert_eq!(latest, Some(version), "publishing a package's first (stable) version must set the `latest` dist-tag to it");
    }

    #[tokio::test]
    async fn each_version_gets_its_own_storage_key_derived_from_name_and_version() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let use_case = PublishNpmPackageUseCase::new(packages, storage.clone(), Arc::new(FakeRepositories::new()), events);
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();

        use_case.execute(repository_id, &name, &v1, serde_json::json!({}), Bytes::from_static(b"v1-bytes"), Uuid::new_v4()).await.unwrap();
        use_case.execute(repository_id, &name, &v2, serde_json::json!({}), Bytes::from_static(b"v2-bytes"), Uuid::new_v4()).await.unwrap();

        assert_eq!(storage.read(repository_id, "left-pad/-/left-pad-1.0.0.tgz").await.unwrap(), b"v1-bytes");
        assert_eq!(storage.read(repository_id, "left-pad/-/left-pad-2.0.0.tgz").await.unwrap(), b"v2-bytes");
    }

    #[tokio::test]
    async fn a_scoped_packages_storage_key_uses_only_the_local_name() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let use_case = PublishNpmPackageUseCase::new(packages, storage.clone(), Arc::new(FakeRepositories::new()), events);
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("@myscope/mypkg").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"bytes"), Uuid::new_v4()).await.unwrap();

        assert_eq!(storage.read(repository_id, "myscope/mypkg/-/mypkg-1.0.0.tgz").await.unwrap(), b"bytes");
    }

    #[tokio::test]
    async fn republishing_the_same_version_is_rejected() {
        let use_case = use_case();
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        let publisher = Uuid::new_v4();
        use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"tarball-bytes"), publisher).await.unwrap();
        let result = use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"other-bytes"), publisher).await;
        assert!(matches!(result, Err(ApplicationError::PackageVersionExists)));
    }

    #[tokio::test]
    async fn publishing_a_prerelease_version_does_not_move_latest() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let use_case = PublishNpmPackageUseCase::new(packages.clone(), storage.clone(), Arc::new(FakeRepositories::new()), events.clone());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let stable = NpmVersion::parse("1.0.0").unwrap();
        let prerelease = NpmVersion::parse("2.0.0-beta.1").unwrap();
        let publisher = Uuid::new_v4();
        use_case.execute(repository_id, &name, &stable, serde_json::json!({}), Bytes::from_static(b"a"), publisher).await.unwrap();
        use_case.execute(repository_id, &name, &prerelease, serde_json::json!({}), Bytes::from_static(b"b"), publisher).await.unwrap();

        let package = packages.packages.lock().unwrap().get(&(repository_id, name.as_str().to_string())).cloned().expect("package should have been created");
        let latest = packages.dist_tags.lock().unwrap().get(&(package.id, "latest".to_string())).cloned();
        assert_eq!(latest, Some(stable), "publishing a prerelease version must not move the `latest` dist-tag");
    }

    fn repo_with_quota(id: Uuid, quota_bytes: Option<i64>) -> hangar_domain::package_repository::PackageRepositorySummary {
        hangar_domain::package_repository::PackageRepositorySummary {
            id,
            organization_id: Uuid::new_v4(),
            name: "left-pad".to_string(),
            format: hangar_domain::package_repository::RepositoryFormat::Npm,
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
    async fn publishing_a_tarball_larger_than_the_quota_is_rejected() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repositories = Arc::new(FakeRepositories::new());
        let events = Arc::new(FakeEvents::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(repo_with_quota(repository_id, Some(5)));
        let use_case = PublishNpmPackageUseCase::new(packages, storage, repositories, events);
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        let result = use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"0123456789"), Uuid::new_v4()).await;

        assert!(matches!(result, Err(ApplicationError::StorageQuotaExceeded)), "got {result:?}");
    }

    #[tokio::test]
    async fn publishing_within_the_quota_succeeds() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repositories = Arc::new(FakeRepositories::new());
        let events = Arc::new(FakeEvents::new());
        let repository_id = Uuid::new_v4();
        repositories.insert(repo_with_quota(repository_id, Some(1024)));
        let use_case = PublishNpmPackageUseCase::new(packages, storage, repositories, events);
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        let result = use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"0123456789"), Uuid::new_v4()).await;

        assert!(result.is_ok(), "got {result:?}");
    }

    #[tokio::test]
    async fn an_unset_quota_never_blocks_a_publish() {
        let use_case = use_case();
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        // No repository was ever inserted into the fake — find_by_id returns
        // None, same as an unlimited repository would.
        let result = use_case.execute(repository_id, &name, &version, serde_json::json!({}), Bytes::from_static(b"0123456789"), Uuid::new_v4()).await;

        assert!(result.is_ok(), "got {result:?}");
    }
}
