use std::sync::Arc;

use hangar_domain::audit::{EventPublisherPort, NpmPackageEvent};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort, NpmVersion};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct DeprecateNpmVersionUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    events: Arc<dyn EventPublisherPort>,
}

impl DeprecateNpmVersionUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>, events: Arc<dyn EventPublisherPort>) -> Self {
        Self { packages, events }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        version: &NpmVersion,
        message: Option<&str>,
        actor_id: Uuid,
    ) -> Result<(), ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        self.packages.find_version(package.id, version).await?.ok_or(ApplicationError::NpmVersionNotFound)?;
        self.packages.set_deprecated(package.id, version, message).await?;
        self.events
            .publish_npm_event(
                NpmPackageEvent::PackageVersionDeprecated {
                    package_name: name.as_str().to_string(),
                    version: version.as_str(),
                    message: message.map(str::to_string),
                },
                package.id,
                Some(actor_id),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeEvents, FakePackages};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion, NpmPackageRepositoryPort};
    use uuid::Uuid;
    use chrono::Utc;
    use std::sync::Arc;

    #[tokio::test]
    async fn deprecating_a_version_sets_the_flag_and_message() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        let package = NpmPackage { id: Uuid::new_v4(), package_repository_id: repository_id, name: name.clone(), created_at: Utc::now(), updated_at: Utc::now(), metadata_fetched_at: None, cached_metadata: None };
        packages.create_package(&package).await.unwrap();
        packages.insert_version(&NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: version.clone(), manifest: serde_json::json!({}),
            shasum: "s".into(), integrity: "i".into(), tarball_storage_key: "k".into(), tarball_size_bytes: 5,
            deprecated: false, deprecated_message: None, published_by: None, published_at: Utc::now(), origin: NpmPackageOrigin::Local,
        }).await.unwrap();

        let use_case = DeprecateNpmVersionUseCase::new(packages.clone(), Arc::new(FakeEvents::new()));
        use_case.execute(repository_id, &name, &version, Some("use left-pad2 instead"), Uuid::new_v4()).await.unwrap();

        let found = packages.find_version(package.id, &version).await.unwrap().unwrap();
        assert!(found.deprecated);
        assert_eq!(found.deprecated_message.as_deref(), Some("use left-pad2 instead"));
    }
}
