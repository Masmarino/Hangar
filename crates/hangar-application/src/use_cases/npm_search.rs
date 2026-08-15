use std::sync::Arc;

use hangar_domain::npm_package::{NpmPackage, NpmPackageRepositoryPort};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct SearchNpmPackagesUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
}

impl SearchNpmPackagesUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>) -> Self {
        Self { packages }
    }

    pub async fn execute(&self, repository_id: Uuid, query: &str, limit: i64) -> Result<Vec<NpmPackage>, ApplicationError> {
        Ok(self.packages.search(repository_id, query, limit).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::FakePackages;
    use hangar_domain::npm_package::NpmPackageName;
    use chrono::Utc;

    #[tokio::test]
    async fn searching_finds_a_package_by_name_substring() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        packages.create_package(&NpmPackage { id: Uuid::new_v4(), package_repository_id: repository_id, name: name.clone(), created_at: Utc::now(), updated_at: Utc::now(), metadata_fetched_at: None, cached_metadata: None }).await.unwrap();

        let use_case = SearchNpmPackagesUseCase::new(packages);
        let results = use_case.execute(repository_id, "left", 20).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, name);
    }
}
