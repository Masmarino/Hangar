use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::audit::{AuditEntry, AuditQueryFilter, EventPublisherPort, NpmPackageEvent, SecurityEvent};
use hangar_domain::error::{DomainError, EventStoreError};
use hangar_domain::npm_audit::{NpmAdvisory, NpmAuditPort};
use hangar_domain::npm_package::{NpmDistTag, NpmPackage, NpmPackageName, NpmPackageRepositoryPort, NpmPackageVersion, NpmVersion};
use hangar_domain::npm_remote::RemoteNpmRegistryPort;
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use hangar_domain::storage::{StorageBackendPort, StorageError};
use uuid::Uuid;

pub struct FakePackages {
    pub packages: Mutex<HashMap<(Uuid, String), NpmPackage>>,
    pub versions: Mutex<HashMap<(Uuid, String), NpmPackageVersion>>,
    pub dist_tags: Mutex<HashMap<(Uuid, String), NpmVersion>>,
}

impl FakePackages {
    pub fn new() -> Self {
        Self { packages: Mutex::new(HashMap::new()), versions: Mutex::new(HashMap::new()), dist_tags: Mutex::new(HashMap::new()) }
    }
}

#[async_trait]
impl NpmPackageRepositoryPort for FakePackages {
    async fn find_package(&self, repository_id: Uuid, name: &hangar_domain::npm_package::NpmPackageName) -> Result<Option<NpmPackage>, DomainError> {
        Ok(self.packages.lock().unwrap().get(&(repository_id, name.as_str().to_string())).cloned())
    }
    async fn find_by_id(&self, id: Uuid) -> Result<Option<NpmPackage>, DomainError> {
        Ok(self.packages.lock().unwrap().values().find(|p| p.id == id).cloned())
    }
    async fn create_package(&self, package: &NpmPackage) -> Result<(), DomainError> {
        self.packages.lock().unwrap().insert((package.package_repository_id, package.name.as_str().to_string()), package.clone());
        Ok(())
    }
    async fn touch_metadata_fetched_at(&self, npm_package_id: Uuid, fetched_at: DateTime<Utc>) -> Result<(), DomainError> {
        let mut packages = self.packages.lock().unwrap();
        if let Some(p) = packages.values_mut().find(|p| p.id == npm_package_id) {
            p.metadata_fetched_at = Some(fetched_at);
        }
        Ok(())
    }
    async fn set_cached_metadata(&self, npm_package_id: Uuid, metadata: serde_json::Value) -> Result<(), DomainError> {
        let mut packages = self.packages.lock().unwrap();
        if let Some(p) = packages.values_mut().find(|p| p.id == npm_package_id) {
            p.cached_metadata = Some(metadata);
        }
        Ok(())
    }
    async fn list_versions(&self, npm_package_id: Uuid) -> Result<Vec<NpmPackageVersion>, DomainError> {
        Ok(self.versions.lock().unwrap().values().filter(|v| v.npm_package_id == npm_package_id).cloned().collect())
    }
    async fn list_versions_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<hangar_domain::npm_package::NpmPackageVersionSummary>, DomainError> {
        Ok(self
            .versions
            .lock()
            .unwrap()
            .values()
            .filter(|v| npm_package_ids.contains(&v.npm_package_id))
            .map(|v| hangar_domain::npm_package::NpmPackageVersionSummary {
                npm_package_id: v.npm_package_id,
                version: v.version.clone(),
                tarball_size_bytes: v.tarball_size_bytes,
                deprecated: v.deprecated,
                published_at: v.published_at,
            })
            .collect())
    }
    async fn find_version(&self, npm_package_id: Uuid, version: &NpmVersion) -> Result<Option<NpmPackageVersion>, DomainError> {
        Ok(self.versions.lock().unwrap().get(&(npm_package_id, version.as_str())).cloned())
    }
    async fn insert_version(&self, version: &NpmPackageVersion) -> Result<(), DomainError> {
        self.versions.lock().unwrap().insert((version.npm_package_id, version.version.as_str()), version.clone());
        Ok(())
    }
    async fn delete_version(&self, npm_package_id: Uuid, version: &NpmVersion) -> Result<(), DomainError> {
        self.versions.lock().unwrap().remove(&(npm_package_id, version.as_str()));
        Ok(())
    }
    async fn delete_package(&self, npm_package_id: Uuid) -> Result<(), DomainError> {
        self.packages.lock().unwrap().retain(|_, p| p.id != npm_package_id);
        self.versions.lock().unwrap().retain(|_, v| v.npm_package_id != npm_package_id);
        Ok(())
    }
    async fn set_deprecated(&self, npm_package_id: Uuid, version: &NpmVersion, message: Option<&str>) -> Result<(), DomainError> {
        if let Some(v) = self.versions.lock().unwrap().get_mut(&(npm_package_id, version.as_str())) {
            v.deprecated = true;
            v.deprecated_message = message.map(str::to_string);
        }
        Ok(())
    }
    async fn list_dist_tags(&self, npm_package_id: Uuid) -> Result<Vec<NpmDistTag>, DomainError> {
        Ok(self.dist_tags.lock().unwrap().iter().filter(|((id, _), _)| *id == npm_package_id)
            .map(|((_, tag), version)| NpmDistTag { npm_package_id, tag: tag.clone(), version: version.clone() }).collect())
    }
    async fn list_dist_tags_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<NpmDistTag>, DomainError> {
        Ok(self.dist_tags.lock().unwrap().iter().filter(|((id, _), _)| npm_package_ids.contains(id))
            .map(|((id, tag), version)| NpmDistTag { npm_package_id: *id, tag: tag.clone(), version: version.clone() }).collect())
    }
    async fn set_dist_tag(&self, npm_package_id: Uuid, tag: &str, version: &NpmVersion) -> Result<(), DomainError> {
        self.dist_tags.lock().unwrap().insert((npm_package_id, tag.to_string()), version.clone());
        Ok(())
    }
    async fn delete_dist_tag(&self, npm_package_id: Uuid, tag: &str) -> Result<(), DomainError> {
        self.dist_tags.lock().unwrap().remove(&(npm_package_id, tag.to_string()));
        Ok(())
    }
    async fn search(&self, repository_id: Uuid, query: &str, limit: i64) -> Result<Vec<NpmPackage>, DomainError> {
        Ok(self.packages.lock().unwrap().values()
            .filter(|p| p.package_repository_id == repository_id && p.name.as_str().contains(query))
            .take(limit.max(0) as usize).cloned().collect())
    }
    async fn increment_download_counter(&self, _npm_package_version_id: Uuid) -> Result<(), DomainError> { Ok(()) }
}

pub struct FakeRemoteRegistry {
    pub metadata_response: Mutex<Option<serde_json::Value>>,
    /// Per-package-name overrides, checked before falling back to `metadata_response`.
    pub per_package: Mutex<HashMap<String, serde_json::Value>>,
}

impl FakeRemoteRegistry {
    pub fn new() -> Self {
        Self {
            metadata_response: Mutex::new(Some(serde_json::json!({ "dist-tags": { "latest": "1.0.0" }, "versions": {} }))),
            per_package: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_package(&self, name: &str, packument: serde_json::Value) {
        self.per_package.lock().unwrap().insert(name.to_string(), packument);
    }
}

#[async_trait]
impl RemoteNpmRegistryPort for FakeRemoteRegistry {
    async fn fetch_metadata(
        &self,
        _base_url: &str,
        package_name: &hangar_domain::npm_package::NpmPackageName,
        _username: Option<&str>,
        _password: Option<&str>,
    ) -> Result<serde_json::Value, DomainError> {
        if let Some(packument) = self.per_package.lock().unwrap().get(package_name.as_str()) {
            return Ok(packument.clone());
        }
        self.metadata_response.lock().unwrap().clone().ok_or_else(|| DomainError::Infrastructure("not found".into()))
    }
    async fn fetch_tarball(&self, _base_url: &str, _tarball_url: &str, _username: Option<&str>, _password: Option<&str>) -> Result<Vec<u8>, DomainError> {
        Ok(b"fake-tarball-bytes".to_vec())
    }
}

/// Returns a fixed set of advisories and records the versions/packages it was asked to check.
pub struct FakeNpmAudit {
    advisories: Vec<NpmAdvisory>,
    checked_versions: Mutex<Vec<String>>,
    checked_packages: Mutex<Option<HashMap<String, Vec<String>>>>,
    /// Overrides `check_bulk_raw`'s response when set.
    bulk_response: Mutex<Option<serde_json::Value>>,
}

impl FakeNpmAudit {
    pub fn new(advisories: Vec<NpmAdvisory>) -> Self {
        Self { advisories, checked_versions: Mutex::new(Vec::new()), checked_packages: Mutex::new(None), bulk_response: Mutex::new(None) }
    }

    pub fn checked_versions(&self) -> Vec<String> {
        self.checked_versions.lock().unwrap().clone()
    }

    pub fn checked_packages(&self) -> Option<HashMap<String, Vec<String>>> {
        self.checked_packages.lock().unwrap().clone()
    }

    pub fn set_bulk_response(&self, response: serde_json::Value) {
        *self.bulk_response.lock().unwrap() = Some(response);
    }
}

#[async_trait]
impl NpmAuditPort for FakeNpmAudit {
    async fn check(&self, _name: &NpmPackageName, versions: &[NpmVersion]) -> Result<Vec<NpmAdvisory>, DomainError> {
        *self.checked_versions.lock().unwrap() = versions.iter().map(|v| v.as_str()).collect();
        Ok(self.advisories.clone())
    }

    async fn check_bulk_raw(&self, packages: &HashMap<String, Vec<String>>) -> Result<serde_json::Value, DomainError> {
        *self.checked_packages.lock().unwrap() = Some(packages.clone());
        if let Some(response) = self.bulk_response.lock().unwrap().clone() {
            return Ok(response);
        }
        Ok(serde_json::json!({ "fake-package": self.advisories }))
    }
}

/// Mirrors the Postgres adapter's "insert-only, latest wins by `scanned_at`" semantics.
pub struct FakeDependencyAuditResults {
    saved: Mutex<Vec<hangar_domain::npm_audit::DependencyAuditResult>>,
}

impl FakeDependencyAuditResults {
    pub fn new() -> Self {
        Self { saved: Mutex::new(Vec::new()) }
    }

    pub fn saved(&self) -> Vec<hangar_domain::npm_audit::DependencyAuditResult> {
        self.saved.lock().unwrap().clone()
    }
}

#[async_trait]
impl hangar_domain::npm_audit::DependencyAuditRepositoryPort for FakeDependencyAuditResults {
    async fn save(&self, result: &hangar_domain::npm_audit::DependencyAuditResult) -> Result<(), DomainError> {
        self.saved.lock().unwrap().push(result.clone());
        Ok(())
    }

    async fn find_latest_for_version(&self, npm_package_version_id: Uuid) -> Result<Option<hangar_domain::npm_audit::DependencyAuditResult>, DomainError> {
        Ok(self
            .saved
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.npm_package_version_id == npm_package_version_id)
            .max_by_key(|r| r.scanned_at)
            .cloned())
    }
}

pub struct FakeRepositories {
    pub repositories: Mutex<HashMap<Uuid, PackageRepositorySummary>>,
}

impl FakeRepositories {
    pub fn new() -> Self {
        Self { repositories: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, summary: PackageRepositorySummary) {
        self.repositories.lock().unwrap().insert(summary.id, summary);
    }
}

#[async_trait]
impl PackageRepositoryQueryPort for FakeRepositories {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repositories.lock().unwrap().get(&id).cloned())
    }
    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repositories.lock().unwrap().values().find(|r| r.organization_id == organization_id && r.name == name).cloned())
    }
    async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repositories.lock().unwrap().values().cloned().collect())
    }
}

pub struct FakeStorage {
    pub written: Mutex<HashMap<(Uuid, String), Vec<u8>>>,
}

impl FakeStorage {
    pub fn new() -> Self { Self { written: Mutex::new(HashMap::new()) } }
}

#[async_trait]
impl StorageBackendPort for FakeStorage {
    async fn write(&self, repository_id: Uuid, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.written.lock().unwrap().insert((repository_id, path.to_string()), data.to_vec());
        Ok(())
    }
    async fn read(&self, repository_id: Uuid, path: &str) -> Result<Vec<u8>, StorageError> {
        self.written.lock().unwrap().get(&(repository_id, path.to_string())).cloned()
            .ok_or_else(|| StorageError::NotFound(path.to_string()))
    }
    async fn read_stream(&self, repository_id: Uuid, path: &str) -> Result<hangar_domain::storage::ByteStream, StorageError> {
        let data = self.read(repository_id, path).await?;
        Ok(Box::pin(futures::stream::once(async move { Ok(bytes::Bytes::from(data)) })))
    }
    async fn delete(&self, repository_id: Uuid, path: &str) -> Result<(), StorageError> {
        self.written.lock().unwrap().remove(&(repository_id, path.to_string()));
        Ok(())
    }
    async fn used_bytes(&self, _repository_id: Uuid) -> Result<u64, StorageError> { Ok(0) }
    async fn is_healthy(&self) -> bool { true }
    async fn volume_space(&self) -> Result<hangar_domain::storage::VolumeSpace, StorageError> {
        Ok(hangar_domain::storage::VolumeSpace { total_bytes: 0, free_bytes: 0 })
    }
}

pub struct FakeEvents {
    pub npm_events: Mutex<Vec<(NpmPackageEvent, Uuid, Option<Uuid>)>>,
}

impl FakeEvents {
    pub fn new() -> Self { Self { npm_events: Mutex::new(Vec::new()) } }
}

#[async_trait]
impl EventPublisherPort for FakeEvents {
    async fn publish_security_event(&self, _event: SecurityEvent, _actor_id: Option<Uuid>) -> Result<(), EventStoreError> { Ok(()) }
    async fn query_audit_log(&self, _filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, EventStoreError> { Ok(vec![]) }
    async fn publish_npm_event(&self, event: NpmPackageEvent, npm_package_id: Uuid, actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        self.npm_events.lock().unwrap().push((event, npm_package_id, actor_id));
        Ok(())
    }
    async fn publish_docker_event(&self, _event: hangar_domain::audit::DockerRegistryEvent, _package_repository_id: Uuid, _actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        Ok(())
    }
}
