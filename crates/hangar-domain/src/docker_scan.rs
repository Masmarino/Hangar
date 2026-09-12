use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerVulnerability {
    pub id: String,
    pub package_name: String,
    pub installed_version: String,
    /// `None` when no fix is published yet.
    pub fixed_version: Option<String>,
    /// Trivy's own string (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`UNKNOWN`), not normalized.
    pub severity: String,
    pub title: Option<String>,
    pub primary_url: Option<String>,
}

#[async_trait]
pub trait DockerImageScannerPort: Send + Sync {
    /// `registry_token` is minted for this scan, never a client credential.
    async fn scan(
        &self,
        repository_name: &str,
        image_name: &str,
        reference: &str,
        platform: Option<&str>,
        registry_token: &str,
    ) -> Result<Vec<DockerVulnerability>, DomainError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DockerImageScanResult {
    pub id: Uuid,
    pub docker_manifest_id: Uuid,
    pub scanned_at: DateTime<Utc>,
    pub vulnerabilities: Vec<DockerVulnerability>,
}

#[async_trait]
pub trait DockerImageScanRepositoryPort: Send + Sync {
    async fn save(&self, result: &DockerImageScanResult) -> Result<(), DomainError>;
    async fn find_latest_for_manifest(&self, docker_manifest_id: Uuid) -> Result<Option<DockerImageScanResult>, DomainError>;
    /// Batched form of `find_latest_for_manifest` across several manifests in one query — a manifest never scanned is simply absent from the result.
    async fn find_latest_for_manifests(&self, docker_manifest_ids: &[Uuid]) -> Result<Vec<DockerImageScanResult>, DomainError>;
}
