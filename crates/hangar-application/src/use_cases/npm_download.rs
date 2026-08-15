use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use hangar_domain::npm_package::{NpmPackageName, NpmPackageOrigin, NpmPackageRepositoryPort, NpmPackageVersion, NpmVersion};
use hangar_domain::npm_remote::RemoteNpmRegistryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use hangar_domain::storage::{ByteStream, StorageBackendPort, StorageError};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha512;
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::group_resolve::resolve_in_group;

pub struct DownloadNpmTarballUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    storage: Arc<dyn StorageBackendPort>,
    remote: Arc<dyn RemoteNpmRegistryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
}

impl DownloadNpmTarballUseCase {
    pub fn new(
        packages: Arc<dyn NpmPackageRepositoryPort>,
        storage: Arc<dyn StorageBackendPort>,
        remote: Arc<dyn RemoteNpmRegistryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
    ) -> Self {
        Self { packages, storage, remote, repositories }
    }

    /// Returns `None` if the version isn't known to this repository at all.
    pub async fn execute_hosted(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        version: &NpmVersion,
    ) -> Result<Option<Vec<u8>>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(None);
        };
        let Some(npm_version) = self.packages.find_version(package.id, version).await? else {
            return Ok(None);
        };
        let bytes = self.storage.read(repository_id, &npm_version.tarball_storage_key).await?;
        spawn_download_counter_increment(self.packages.clone(), npm_version.id);
        Ok(Some(bytes))
    }

    pub fn execute<'a>(
        &'a self,
        repository_id: Uuid,
        name: &'a NpmPackageName,
        version: &'a NpmVersion,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<Vec<u8>>, ApplicationError>> + Send + 'a>> {
        resolve_in_group(
            &self.repositories,
            repository_id,
            HashSet::new(),
            move |repository_id| self.execute_hosted(repository_id, name, version),
            move |repository_id, repo| self.execute_proxy(repository_id, repo, name, version),
            || ApplicationError::NpmPackageNotFound,
        )
    }

    /// Same as `execute_hosted`, chunked instead of buffered whole.
    pub async fn execute_hosted_stream(&self, repository_id: Uuid, name: &NpmPackageName, version: &NpmVersion) -> Result<Option<ByteStream>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(None);
        };
        let Some(npm_version) = self.packages.find_version(package.id, version).await? else {
            return Ok(None);
        };
        let stream = self.storage.read_stream(repository_id, &npm_version.tarball_storage_key).await?;
        spawn_download_counter_increment(self.packages.clone(), npm_version.id);
        Ok(Some(stream))
    }

    /// Same as `execute`, chunked instead of buffered whole for the common (already-cached) case. A proxy cache miss still fetches and verifies fully in memory first (`execute_proxy`).
    pub fn execute_stream<'a>(
        &'a self,
        repository_id: Uuid,
        name: &'a NpmPackageName,
        version: &'a NpmVersion,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<ByteStream>, ApplicationError>> + Send + 'a>> {
        resolve_in_group(
            &self.repositories,
            repository_id,
            HashSet::new(),
            move |repository_id| self.execute_hosted_stream(repository_id, name, version),
            move |repository_id, repo| async move {
                let bytes = self.execute_proxy(repository_id, repo, name, version).await?;
                Ok(bytes.map(|b| Box::pin(futures::stream::once(async move { Ok::<_, StorageError>(bytes::Bytes::from(b)) })) as ByteStream))
            },
            || ApplicationError::NpmPackageNotFound,
        )
    }

    async fn execute_proxy(
        &self,
        repository_id: Uuid,
        repo: PackageRepositorySummary,
        name: &NpmPackageName,
        version: &NpmVersion,
    ) -> Result<Option<Vec<u8>>, ApplicationError> {
        // Tarballs are immutable once fetched, so a cached one is served directly.
        if let Some(bytes) = self.execute_hosted(repository_id, name, version).await? {
            return Ok(Some(bytes));
        }

        // Not cached: the tarball URL must come from the cached metadata document.
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(None);
        };
        let Some(cached) = package.cached_metadata.as_ref() else {
            return Ok(None);
        };
        let Some(tarball_url) = cached
            .get("versions")
            .and_then(|v| v.get(version.as_str()))
            .and_then(|v| v.get("dist"))
            .and_then(|d| d.get("tarball"))
            .and_then(|t| t.as_str())
        else {
            return Ok(None);
        };

        let remote_url = repo
            .remote_url
            .as_deref()
            .ok_or_else(|| ApplicationError::InvalidNpmPayload("proxy repository has no remote_url configured".into()))?;
        let tarball_bytes = self.remote.fetch_tarball(remote_url, tarball_url, repo.remote_username.as_deref(), repo.remote_password.as_deref()).await?;

        let manifest = cached
            .get("versions")
            .and_then(|v| v.get(version.as_str()))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // Computed server-side — never trust the remote's declared shasum/integrity. Hashing is CPU-bound, off the async executor so it doesn't stall other requests.
        let (shasum, integrity, tarball_bytes) = tokio::task::spawn_blocking(move || {
            let shasum = hex::encode(Sha1::digest(&tarball_bytes));
            let integrity = format!("sha512-{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, Sha512::digest(&tarball_bytes)));
            (shasum, integrity, tarball_bytes)
        })
        .await
        .map_err(|e| hangar_domain::error::DomainError::Infrastructure(e.to_string()))?;

        let filename = format!("{}-{}.tgz", name.as_str().rsplit('/').next().unwrap_or(name.as_str()), version.as_str());
        let storage_key = format!("{}/-/{filename}", name.as_str().trim_start_matches('@'));
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
            published_by: None,
            published_at: Utc::now(),
            origin: NpmPackageOrigin::ProxyCache,
        };
        self.packages.insert_version(&npm_version).await?;
        spawn_download_counter_increment(self.packages.clone(), npm_version.id);
        Ok(Some(tarball_bytes))
    }
}

/// Best-effort statistic, not part of the response contract — spawned off the response path so a slow or failed counter write never adds latency to an actual download.
fn spawn_download_counter_increment(packages: Arc<dyn NpmPackageRepositoryPort>, npm_version_id: Uuid) {
    tokio::spawn(async move {
        let _ = packages.increment_download_counter(npm_version_id).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakePackages, FakeRemoteRegistry, FakeStorage};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};
    use hangar_domain::package_repository::RepositoryType;

    #[tokio::test]
    async fn downloading_an_already_stored_hosted_tarball_reads_it_back_unchanged() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
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
        storage.write(repository_id, "left-pad/-/left-pad-1.0.0.tgz", b"real-bytes").await.unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: version.clone(),
                manifest: serde_json::json!({}),
                shasum: "s".into(),
                integrity: "i".into(),
                tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(),
                tarball_size_bytes: 10,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();

        let use_case = DownloadNpmTarballUseCase::new(
            packages,
            storage,
            Arc::new(FakeRemoteRegistry::new()),
            Arc::new(crate::use_cases::npm_test_support::FakeRepositories::new()),
        );
        let bytes = use_case.execute_hosted(repository_id, &name, &version).await.unwrap();
        assert_eq!(bytes.as_deref(), Some(b"real-bytes".as_slice()));
    }

    #[tokio::test]
    async fn execute_hosted_stream_yields_the_same_bytes_as_execute_hosted() {
        use futures::StreamExt;

        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
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
        storage.write(repository_id, "left-pad/-/left-pad-1.0.0.tgz", b"streamed-bytes").await.unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: version.clone(),
                manifest: serde_json::json!({}),
                shasum: "s".into(),
                integrity: "i".into(),
                tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(),
                tarball_size_bytes: 14,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();

        let use_case = DownloadNpmTarballUseCase::new(
            packages,
            storage,
            Arc::new(FakeRemoteRegistry::new()),
            Arc::new(crate::use_cases::npm_test_support::FakeRepositories::new()),
        );
        let mut stream = use_case.execute_hosted_stream(repository_id, &name, &version).await.unwrap().unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"streamed-bytes");
    }

    #[tokio::test]
    async fn downloading_a_missing_hosted_version_returns_none() {
        let use_case = DownloadNpmTarballUseCase::new(
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            Arc::new(FakeRemoteRegistry::new()),
            Arc::new(crate::use_cases::npm_test_support::FakeRepositories::new()),
        );
        let result = use_case
            .execute_hosted(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap(), &NpmVersion::parse("1.0.0").unwrap())
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn downloading_via_a_proxy_repository_lazily_fetches_and_caches_the_tarball() {
        let packages = Arc::new(FakePackages::new());
        let storage = Arc::new(FakeStorage::new());
        let repositories = Arc::new(crate::use_cases::npm_test_support::FakeRepositories::new());
        let repository_id = Uuid::new_v4();
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repository_id,
            organization_id: Uuid::new_v4(),
            name: "proxy-repo".to_string(),
            format: hangar_domain::package_repository::RepositoryFormat::Npm,
            repo_type: RepositoryType::Proxy,
            remote_url: Some("https://registry.example.com".to_string()),
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
        });

        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: name.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: Some(Utc::now()),
            cached_metadata: Some(serde_json::json!({
                "versions": {
                    "1.0.0": {
                        "dist": {
                            "tarball": "https://registry.example.com/left-pad/-/left-pad-1.0.0.tgz",
                            "integrity": "sha512-fake"
                        }
                    }
                }
            })),
        };
        packages.create_package(&package).await.unwrap();

        let packages_inspect = packages.clone();
        let use_case = DownloadNpmTarballUseCase::new(packages, storage, Arc::new(FakeRemoteRegistry::new()), repositories);
        let bytes = use_case.execute(repository_id, &name, &version).await.unwrap();
        assert_eq!(bytes.as_deref(), Some(b"fake-tarball-bytes".as_slice()));

        let expected_shasum = hex::encode(Sha1::digest(b"fake-tarball-bytes"));
        let expected_integrity = format!(
            "sha512-{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, Sha512::digest(b"fake-tarball-bytes"))
        );
        let stored_version = packages_inspect
            .versions
            .lock()
            .unwrap()
            .get(&(package.id, version.as_str()))
            .cloned()
            .expect("proxy-cached version must be persisted");
        assert_eq!(stored_version.shasum, expected_shasum);
        assert_eq!(stored_version.integrity, expected_integrity);
        assert_ne!(stored_version.integrity, "sha512-fake", "must not trust the remote's declared integrity");
        assert_eq!(stored_version.origin, NpmPackageOrigin::ProxyCache);

        let bytes_again = use_case.execute_hosted(repository_id, &name, &version).await.unwrap();
        assert_eq!(bytes_again.as_deref(), Some(b"fake-tarball-bytes".as_slice()));
    }

    #[tokio::test]
    async fn a_cyclic_group_configuration_resolves_without_hanging() {
        let repo_a_id = Uuid::new_v4();
        let repo_b_id = Uuid::new_v4();

        let repositories = Arc::new(crate::use_cases::npm_test_support::FakeRepositories::new());
        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repo_a_id,
            organization_id: Uuid::new_v4(),
            name: "group-a".to_string(),
            format: hangar_domain::package_repository::RepositoryFormat::Npm,
            repo_type: RepositoryType::Group,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_b_id],
        });
        repositories.insert(hangar_domain::package_repository::PackageRepositorySummary {
            id: repo_b_id,
            organization_id: Uuid::new_v4(),
            name: "group-b".to_string(),
            format: hangar_domain::package_repository::RepositoryFormat::Npm,
            repo_type: RepositoryType::Group,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            quota_bytes: None, retention_keep_last_n: None, group_members: vec![repo_a_id],
        });

        let use_case = DownloadNpmTarballUseCase::new(
            Arc::new(FakePackages::new()),
            Arc::new(FakeStorage::new()),
            Arc::new(FakeRemoteRegistry::new()),
            repositories,
        );
        let name = NpmPackageName::parse("left-pad").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), use_case.execute(repo_a_id, &name, &version))
            .await
            .expect("execute() must not hang on a cyclic group configuration");
        assert!(result.unwrap().is_none());
    }
}
