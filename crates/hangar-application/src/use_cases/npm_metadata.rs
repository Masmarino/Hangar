use std::collections::HashSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use hangar_domain::npm_package::{NpmDistTag, NpmPackageName, NpmPackageRepositoryPort, NpmPackageVersion};
use hangar_domain::npm_remote::RemoteNpmRegistryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use serde_json::json;
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::group_resolve::resolve_in_group;

const PROXY_METADATA_TTL: Duration = Duration::minutes(5);

pub struct GetNpmPackageMetadataUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    remote: Arc<dyn RemoteNpmRegistryPort>,
}

impl GetNpmPackageMetadataUseCase {
    pub fn new(
        packages: Arc<dyn NpmPackageRepositoryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        remote: Arc<dyn RemoteNpmRegistryPort>,
    ) -> Self {
        Self { packages, repositories, remote }
    }

    /// Also used for proxy repositories once their cache is refreshed.
    pub async fn execute_hosted(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
    ) -> Result<Option<serde_json::Value>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(None);
        };
        let versions = self.packages.list_versions(package.id).await?;
        if versions.is_empty() {
            return Ok(None);
        }
        let dist_tags = self.packages.list_dist_tags(package.id).await?;
        Ok(Some(build_metadata_document(name, versions, &dist_tags)))
    }

    pub fn execute<'a>(
        &'a self,
        repository_id: Uuid,
        name: &'a NpmPackageName,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<serde_json::Value>, ApplicationError>> + Send + 'a>> {
        resolve_in_group(
            &self.repositories,
            repository_id,
            HashSet::new(),
            move |repository_id| self.execute_hosted(repository_id, name),
            move |repository_id, repo| self.execute_proxy(repository_id, repo, name),
            || ApplicationError::NpmPackageNotFound,
        )
    }

    async fn execute_proxy(
        &self,
        repository_id: Uuid,
        repo: PackageRepositorySummary,
        name: &NpmPackageName,
    ) -> Result<Option<serde_json::Value>, ApplicationError> {
        let existing = self.packages.find_package(repository_id, name).await?;
        let stale = match &existing {
            None => true,
            Some(p) => p.metadata_fetched_at.is_none_or(|fetched_at| Utc::now() - fetched_at > PROXY_METADATA_TTL),
        };

        if stale {
            let remote_url = repo
                .remote_url
                .as_deref()
                .ok_or_else(|| ApplicationError::InvalidNpmPayload("proxy repository has no remote_url configured".into()))?;
            match self.remote.fetch_metadata(remote_url, name, repo.remote_username.as_deref(), repo.remote_password.as_deref()).await {
                Ok(document) => {
                    let package_id = match &existing {
                        Some(p) => p.id,
                        None => {
                            let created = hangar_domain::npm_package::NpmPackage {
                                id: Uuid::new_v4(),
                                package_repository_id: repository_id,
                                name: name.clone(),
                                created_at: Utc::now(),
                                updated_at: Utc::now(),
                                metadata_fetched_at: None,
                                cached_metadata: None,
                            };
                            self.packages.create_package(&created).await?;
                            created.id
                        }
                    };
                    self.packages.set_cached_metadata(package_id, document).await?;
                    self.packages.touch_metadata_fetched_at(package_id, Utc::now()).await?;
                }
                // Remote unreachable, but we have a stale cache — serve it rather than fail.
                Err(_e) if existing.is_some() => {}
                Err(e) => return Err(e.into()),
            }
        }

        Ok(self.packages.find_package(repository_id, name).await?.and_then(|p| p.cached_metadata))
    }
}

fn build_metadata_document(name: &NpmPackageName, versions: Vec<NpmPackageVersion>, dist_tags: &[NpmDistTag]) -> serde_json::Value {
    let mut versions_doc = serde_json::Map::new();
    for v in versions {
        let mut manifest = v.manifest;
        if let Some(obj) = manifest.as_object_mut() {
            obj.insert("dist".to_string(), json!({ "shasum": v.shasum, "integrity": v.integrity }));
            // npm's protocol wants the deprecation message as the field's value; absence means "not deprecated".
            if v.deprecated {
                if let Some(message) = &v.deprecated_message {
                    obj.insert("deprecated".to_string(), json!(message));
                }
            }
        }
        versions_doc.insert(v.version.as_str(), manifest);
    }
    let dist_tags_doc: serde_json::Map<String, serde_json::Value> =
        dist_tags.iter().map(|t| (t.tag.clone(), json!(t.version.as_str()))).collect();
    json!({
        "_id": name.as_str(),
        "name": name.as_str(),
        "dist-tags": dist_tags_doc,
        "versions": versions_doc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakePackages, FakeRemoteRegistry, FakeRepositories};
    use chrono::Utc;
    use hangar_domain::npm_package::NpmPackageName;
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};

    #[tokio::test]
    async fn a_hosted_repository_serves_its_own_published_versions() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let package = hangar_domain::npm_package::NpmPackage {
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
            .insert_version(&hangar_domain::npm_package::NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: hangar_domain::npm_package::NpmVersion::parse("1.0.0").unwrap(),
                manifest: json!({ "name": "left-pad", "version": "1.0.0" }),
                shasum: "abc".to_string(),
                integrity: "sha512-abc".to_string(),
                tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".to_string(),
                tarball_size_bytes: 100,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: Utc::now(),
                origin: hangar_domain::npm_package::NpmPackageOrigin::Local,
            })
            .await
            .unwrap();

        let use_case = GetNpmPackageMetadataUseCase::new(
            packages,
            Arc::new(FakeRepositories::new()),
            Arc::new(FakeRemoteRegistry::new()),
        );
        let doc = use_case.execute_hosted(repository_id, &name).await.unwrap();
        assert!(doc.is_some());
    }

    #[tokio::test]
    async fn a_deprecated_versions_metadata_document_carries_the_deprecated_field() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let package = hangar_domain::npm_package::NpmPackage {
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
            .insert_version(&hangar_domain::npm_package::NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: hangar_domain::npm_package::NpmVersion::parse("1.0.0").unwrap(),
                manifest: json!({ "name": "left-pad", "version": "1.0.0" }),
                shasum: "abc".to_string(),
                integrity: "sha512-abc".to_string(),
                tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".to_string(),
                tarball_size_bytes: 100,
                deprecated: true,
                deprecated_message: Some("use left-pad2 instead".to_string()),
                published_by: None,
                published_at: Utc::now(),
                origin: hangar_domain::npm_package::NpmPackageOrigin::Local,
            })
            .await
            .unwrap();

        let use_case = GetNpmPackageMetadataUseCase::new(
            packages,
            Arc::new(FakeRepositories::new()),
            Arc::new(FakeRemoteRegistry::new()),
        );
        let doc = use_case.execute_hosted(repository_id, &name).await.unwrap().unwrap();
        assert_eq!(doc["versions"]["1.0.0"]["deprecated"], json!("use left-pad2 instead"));
    }

    #[tokio::test]
    async fn a_hosted_repository_without_the_package_returns_none() {
        let use_case = GetNpmPackageMetadataUseCase::new(
            Arc::new(FakePackages::new()),
            Arc::new(FakeRepositories::new()),
            Arc::new(FakeRemoteRegistry::new()),
        );
        let doc = use_case.execute_hosted(Uuid::new_v4(), &NpmPackageName::parse("missing").unwrap()).await.unwrap();
        assert!(doc.is_none());
    }

    /// `timeout` so a regression (removing the visited-set guard) fails fast instead of hanging.
    #[tokio::test]
    async fn a_cyclic_group_configuration_resolves_without_hanging() {
        let repo_a_id = Uuid::new_v4();
        let repo_b_id = Uuid::new_v4();

        let repositories = Arc::new(FakeRepositories::new());
        repositories.insert(PackageRepositorySummary {
            id: repo_a_id,
            organization_id: Uuid::new_v4(),
            name: "group-a".to_string(),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Group,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_b_id],
        });
        repositories.insert(PackageRepositorySummary {
            id: repo_b_id,
            organization_id: Uuid::new_v4(),
            name: "group-b".to_string(),
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Group,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_a_id],
        });

        let use_case = GetNpmPackageMetadataUseCase::new(
            Arc::new(FakePackages::new()),
            repositories,
            Arc::new(FakeRemoteRegistry::new()),
        );
        let name = NpmPackageName::parse("left-pad").unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), use_case.execute(repo_a_id, &name))
            .await
            .expect("execute() must not hang on a cyclic group configuration");
        assert!(result.unwrap().is_none());
    }
}
