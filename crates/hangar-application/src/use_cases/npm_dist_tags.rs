use std::sync::Arc;

use hangar_domain::audit::{EventPublisherPort, NpmPackageEvent};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort, NpmVersion};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct SetDistTagUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    events: Arc<dyn EventPublisherPort>,
}

impl SetDistTagUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>, events: Arc<dyn EventPublisherPort>) -> Self {
        Self { packages, events }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        tag: &str,
        version: &NpmVersion,
        actor_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        self.packages.find_version(package.id, version).await?.ok_or(ApplicationError::NpmVersionNotFound)?;
        self.packages.set_dist_tag(package.id, tag, version).await?;
        self.events
            .publish_npm_event(
                NpmPackageEvent::DistTagChanged { package_name: name.as_str().to_string(), tag: tag.to_string(), version: version.as_str() },
                package.id,
                Some(actor_id),
            )
            .await?;
        Ok(())
    }
}

pub struct ListDistTagsUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
}

impl ListDistTagsUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>) -> Self {
        Self { packages }
    }

    pub async fn execute(&self, repository_id: Uuid, name: &NpmPackageName) -> Result<Vec<hangar_domain::npm_package::NpmDistTag>, ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        Ok(self.packages.list_dist_tags(package.id).await?)
    }
}

pub struct DeleteDistTagUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
}

impl DeleteDistTagUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>) -> Self {
        Self { packages }
    }

    pub async fn execute(&self, repository_id: Uuid, name: &NpmPackageName, tag: &str) -> Result<(), ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        self.packages.delete_dist_tag(package.id, tag).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeEvents, FakePackages};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageOrigin, NpmPackageVersion};
    use chrono::Utc;

    async fn seed_package_with_version(packages: &FakePackages, repository_id: Uuid, name: &NpmPackageName, version: &NpmVersion) -> Uuid {
        let package = NpmPackage { id: Uuid::new_v4(), package_repository_id: repository_id, name: name.clone(), created_at: Utc::now(), updated_at: Utc::now(), metadata_fetched_at: None, cached_metadata: None };
        packages.create_package(&package).await.unwrap();
        packages.insert_version(&NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: version.clone(), manifest: serde_json::json!({}),
            shasum: "s".into(), integrity: "i".into(), tarball_storage_key: "k".into(), tarball_size_bytes: 1,
            deprecated: false, deprecated_message: None, published_by: None, published_at: Utc::now(), origin: NpmPackageOrigin::Local,
        }).await.unwrap();
        package.id
    }

    #[tokio::test]
    async fn setting_a_dist_tag_on_an_existing_version_succeeds() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        let package_id = seed_package_with_version(&packages, repository_id, &name, &version).await;

        let use_case = SetDistTagUseCase::new(packages.clone(), Arc::new(FakeEvents::new()));
        use_case.execute(repository_id, &name, "beta", &version, Uuid::new_v4()).await.unwrap();

        let tags = packages.list_dist_tags(package_id).await.unwrap();
        assert!(tags.iter().any(|t| t.tag == "beta" && t.version == version));
    }

    #[tokio::test]
    async fn setting_a_dist_tag_on_an_unknown_package_is_an_error() {
        let use_case = SetDistTagUseCase::new(Arc::new(FakePackages::new()), Arc::new(FakeEvents::new()));
        let result = use_case.execute(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap(), "beta", &NpmVersion::parse("1.0.0").unwrap(), Uuid::new_v4()).await;
        assert!(matches!(result, Err(ApplicationError::NpmPackageNotFound)));
    }

    #[tokio::test]
    async fn listing_dist_tags_returns_the_tags_set_on_the_package() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let latest = NpmVersion::parse("1.0.0").unwrap();
        let beta = NpmVersion::parse("2.0.0-beta.0").unwrap();
        let package_id = seed_package_with_version(&packages, repository_id, &name, &latest).await;
        packages.insert_version(&NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package_id, version: beta.clone(), manifest: serde_json::json!({}),
            shasum: "s".into(), integrity: "i".into(), tarball_storage_key: "k".into(), tarball_size_bytes: 1,
            deprecated: false, deprecated_message: None, published_by: None, published_at: Utc::now(), origin: NpmPackageOrigin::Local,
        }).await.unwrap();
        packages.set_dist_tag(package_id, "latest", &latest).await.unwrap();
        packages.set_dist_tag(package_id, "beta", &beta).await.unwrap();

        let use_case = ListDistTagsUseCase::new(packages);
        let tags = use_case.execute(repository_id, &name).await.unwrap();

        assert_eq!(tags.len(), 2);
        assert!(tags.iter().any(|t| t.tag == "latest" && t.version == latest));
        assert!(tags.iter().any(|t| t.tag == "beta" && t.version == beta));
    }

    #[tokio::test]
    async fn listing_dist_tags_on_an_unknown_package_is_an_error() {
        let use_case = ListDistTagsUseCase::new(Arc::new(FakePackages::new()));
        let result = use_case.execute(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap()).await;
        assert!(matches!(result, Err(ApplicationError::NpmPackageNotFound)));
    }

    #[tokio::test]
    async fn setting_a_dist_tag_on_an_unknown_version_is_an_error() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let existing_version = NpmVersion::parse("1.0.0").unwrap();
        let missing_version = NpmVersion::parse("2.0.0").unwrap();

        seed_package_with_version(&packages, repository_id, &name, &existing_version).await;

        let use_case = SetDistTagUseCase::new(packages.clone(), Arc::new(FakeEvents::new()));
        let result = use_case.execute(repository_id, &name, "beta", &missing_version, Uuid::new_v4()).await;
        assert!(matches!(result, Err(ApplicationError::NpmVersionNotFound)));
    }
}
