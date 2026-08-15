use std::collections::HashMap;
use std::sync::Arc;

use hangar_domain::npm_audit::{NpmAdvisory, NpmAuditPort};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort};
use uuid::Uuid;

use crate::error::ApplicationError;

/// A package that doesn't exist audits clean rather than erroring.
pub struct AuditNpmPackageUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    audit: Arc<dyn NpmAuditPort>,
}

impl AuditNpmPackageUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>, audit: Arc<dyn NpmAuditPort>) -> Self {
        Self { packages, audit }
    }

    pub async fn execute(&self, repository_id: Uuid, name: &NpmPackageName) -> Result<Vec<NpmAdvisory>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(Vec::new());
        };
        let versions = self.packages.list_versions(package.id).await?;
        let versions: Vec<_> = versions.into_iter().map(|v| v.version).collect();
        Ok(self.audit.check(name, &versions).await?)
    }
}

/// Unlike `AuditNpmPackageUseCase`, forwards the client's request straight to npm's advisory database rather than looking anything up in Hangar's own storage.
pub struct BulkAuditNpmPackagesUseCase {
    audit: Arc<dyn NpmAuditPort>,
}

impl BulkAuditNpmPackagesUseCase {
    pub fn new(audit: Arc<dyn NpmAuditPort>) -> Self {
        Self { audit }
    }

    pub async fn execute(&self, packages: &HashMap<String, Vec<String>>) -> Result<serde_json::Value, ApplicationError> {
        Ok(self.audit.check_bulk_raw(packages).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeNpmAudit, FakePackages};
    use chrono::Utc;
    use hangar_domain::npm_package::{NpmPackage, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

    fn sample_advisory(id: i64) -> NpmAdvisory {
        NpmAdvisory {
            id,
            url: format!("https://github.com/advisories/GHSA-{id}"),
            title: "Prototype Pollution".to_string(),
            severity: "critical".to_string(),
            vulnerable_versions: "<1.0.0".to_string(),
            cwe: vec!["CWE-1321".to_string()],
            cvss_score: Some(9.8),
        }
    }

    #[tokio::test]
    async fn audits_every_stored_version_of_the_package() {
        let packages = Arc::new(FakePackages::new());
        let audit = Arc::new(FakeNpmAudit::new(vec![sample_advisory(1)]));
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: name.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        packages.create_package(&package).await.unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: NpmVersion::parse("1.0.0").unwrap(),
                manifest: serde_json::json!({}),
                shasum: "s".to_string(),
                integrity: "i".to_string(),
                tarball_storage_key: "k".to_string(),
                tarball_size_bytes: 1,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();

        let use_case = AuditNpmPackageUseCase::new(packages, audit.clone());
        let advisories = use_case.execute(repository_id, &name).await.unwrap();

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, 1);
        assert_eq!(audit.checked_versions(), vec!["1.0.0".to_string()]);
    }

    #[tokio::test]
    async fn an_unknown_package_audits_clean_without_calling_the_audit_port() {
        let packages = Arc::new(FakePackages::new());
        let audit = Arc::new(FakeNpmAudit::new(vec![sample_advisory(1)]));

        let use_case = AuditNpmPackageUseCase::new(packages, audit.clone());
        let advisories = use_case.execute(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap()).await.unwrap();

        assert!(advisories.is_empty());
        assert!(audit.checked_versions().is_empty());
    }

    #[tokio::test]
    async fn bulk_audit_forwards_exactly_what_the_client_sent_to_the_audit_port() {
        let audit = Arc::new(FakeNpmAudit::new(vec![sample_advisory(1)]));
        let mut packages = HashMap::new();
        packages.insert("left-pad".to_string(), vec!["1.0.0".to_string(), "1.1.0".to_string()]);
        packages.insert("minimist".to_string(), vec!["0.0.8".to_string()]);

        let use_case = BulkAuditNpmPackagesUseCase::new(audit.clone());
        let result = use_case.execute(&packages).await.unwrap();

        assert_eq!(audit.checked_packages(), Some(packages));
        assert!(result.get("fake-package").is_some());
    }
}
