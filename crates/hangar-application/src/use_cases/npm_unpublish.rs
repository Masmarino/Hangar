use std::sync::Arc;

use hangar_domain::audit::{EventPublisherPort, NpmPackageEvent};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort, NpmVersion};
use hangar_domain::storage::StorageBackendPort;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct UnpublishNpmPackageUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    storage: Arc<dyn StorageBackendPort>,
    events: Arc<dyn EventPublisherPort>,
}

impl UnpublishNpmPackageUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>, storage: Arc<dyn StorageBackendPort>, events: Arc<dyn EventPublisherPort>) -> Self {
        Self { packages, storage, events }
    }

    pub async fn execute_version(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        version: &NpmVersion,
        actor_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        let npm_version = self.packages.find_version(package.id, version).await?.ok_or(ApplicationError::NpmVersionNotFound)?;

        self.storage.delete(repository_id, &npm_version.tarball_storage_key).await?;
        self.packages.delete_version(package.id, version).await?;

        // A dist-tag left pointing at a removed version would make npm install unresolvable.
        for tag in self.packages.list_dist_tags(package.id).await? {
            if tag.version == *version {
                self.packages.delete_dist_tag(package.id, &tag.tag).await?;
            }
        }

        self.events
            .publish_npm_event(
                NpmPackageEvent::PackageVersionUnpublished { package_name: name.as_str().to_string(), version: version.as_str() },
                package.id,
                Some(actor_id),
            )
            .await?;

        if self.packages.list_versions(package.id).await?.is_empty() {
            self.packages.delete_package(package.id).await?;
            self.events
                .publish_npm_event(NpmPackageEvent::PackageDeleted { package_name: name.as_str().to_string() }, package.id, Some(actor_id))
                .await?;
        }

        Ok(())
    }

    pub async fn execute_whole_package(&self, repository_id: Uuid, name: &NpmPackageName, actor_id: Uuid) -> Result<(), ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        for version in self.packages.list_versions(package.id).await? {
            self.storage.delete(repository_id, &version.tarball_storage_key).await?;
        }
        self.packages.delete_package(package.id).await?;
        self.events
            .publish_npm_event(NpmPackageEvent::PackageDeleted { package_name: name.as_str().to_string() }, package.id, Some(actor_id))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeEvents, FakePackages, FakeStorage};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion, NpmPackageRepositoryPort};
    use hangar_domain::storage::StorageBackendPort;
    use uuid::Uuid;
    use chrono::Utc;
    use std::sync::Arc;

    async fn seed_one_version(packages: &FakePackages, storage: &FakeStorage, repository_id: Uuid, name: &NpmPackageName, version: &NpmVersion) -> Uuid {
        let package = NpmPackage { id: Uuid::new_v4(), package_repository_id: repository_id, name: name.clone(), created_at: Utc::now(), updated_at: Utc::now(), metadata_fetched_at: None, cached_metadata: None };
        packages.create_package(&package).await.unwrap();
        storage.write(repository_id, "left-pad/-/left-pad-1.0.0.tgz", b"bytes").await.unwrap();
        packages.insert_version(&NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: version.clone(), manifest: serde_json::json!({}),
            shasum: "s".into(), integrity: "i".into(), tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(),
            tarball_size_bytes: 5, deprecated: false, deprecated_message: None, published_by: None, published_at: Utc::now(),
            origin: NpmPackageOrigin::Local,
        }).await.unwrap();
        package.id
    }

    #[tokio::test]
    async fn unpublishing_the_only_version_deletes_the_whole_package() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        let actor_id = Uuid::new_v4();
        seed_one_version(&packages, &storage, repository_id, &name, &version).await;

        assert!(storage.written.lock().unwrap().contains_key(&(repository_id, "left-pad/-/left-pad-1.0.0.tgz".to_string())));

        let use_case = UnpublishNpmPackageUseCase::new(packages.clone(), storage.clone(), events.clone());
        use_case.execute_version(repository_id, &name, &version, actor_id).await.unwrap();

        assert!(packages.find_package(repository_id, &name).await.unwrap().is_none());

        assert!(!storage.written.lock().unwrap().contains_key(&(repository_id, "left-pad/-/left-pad-1.0.0.tgz".to_string())));
        assert!(storage.written.lock().unwrap().is_empty(), "storage should be empty after unpublishing the last version");

        let published_events = events.npm_events.lock().unwrap();
        assert_eq!(published_events.len(), 2, "expected exactly 2 events for unpublishing the last version");

        match &published_events[0].0 {
            NpmPackageEvent::PackageVersionUnpublished { package_name, version: v } => {
                assert_eq!(package_name, "left-pad");
                assert_eq!(v, "1.0.0");
            }
            _ => panic!("first event should be PackageVersionUnpublished"),
        }

        match &published_events[1].0 {
            NpmPackageEvent::PackageDeleted { package_name } => {
                assert_eq!(package_name, "left-pad");
            }
            _ => panic!("second event should be PackageDeleted"),
        }

        assert_eq!(published_events[0].2, Some(actor_id));
        assert_eq!(published_events[1].2, Some(actor_id));
    }

    #[tokio::test]
    async fn unpublishing_a_missing_version_is_an_error() {
        let use_case = UnpublishNpmPackageUseCase::new(Arc::new(FakePackages::new()), Arc::new(FakeStorage::new()), Arc::new(FakeEvents::new()));
        let result = use_case.execute_version(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap(), &NpmVersion::parse("1.0.0").unwrap(), Uuid::new_v4()).await;
        assert!(matches!(result, Err(crate::error::ApplicationError::NpmPackageNotFound)));
    }

    #[tokio::test]
    async fn unpublishing_the_version_a_dist_tag_points_at_removes_the_dangling_tag() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let events = Arc::new(FakeEvents::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        let actor_id = Uuid::new_v4();

        let package_id = seed_one_version(&packages, &storage, repository_id, &name, &v1).await;
        storage.write(repository_id, "left-pad/-/left-pad-2.0.0.tgz", b"bytes").await.unwrap();
        packages.insert_version(&NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package_id, version: v2.clone(), manifest: serde_json::json!({}),
            shasum: "s2".into(), integrity: "i2".into(), tarball_storage_key: "left-pad/-/left-pad-2.0.0.tgz".into(),
            tarball_size_bytes: 5, deprecated: false, deprecated_message: None, published_by: None, published_at: Utc::now(),
            origin: NpmPackageOrigin::Local,
        }).await.unwrap();

        // `latest` points at the version we're about to unpublish.
        packages.set_dist_tag(package_id, "latest", &v2).await.unwrap();
        assert_eq!(packages.list_dist_tags(package_id).await.unwrap().len(), 1);

        let use_case = UnpublishNpmPackageUseCase::new(packages.clone(), storage.clone(), events.clone());
        use_case.execute_version(repository_id, &name, &v2, actor_id).await.unwrap();

        let remaining_tags = packages.list_dist_tags(package_id).await.unwrap();
        assert!(
            remaining_tags.iter().all(|t| t.tag != "latest"),
            "dangling `latest` dist-tag should have been removed when the version it pointed at was unpublished, found: {remaining_tags:?}"
        );

        // The other version is untouched, and the package itself still exists
        // (v1 remains), so this isn't just an artifact of the whole-package
        // cascade deleting the dist-tags table wholesale.
        assert!(packages.find_package(repository_id, &name).await.unwrap().is_some());
        assert!(packages.find_version(package_id, &v1).await.unwrap().is_some());
    }
}
