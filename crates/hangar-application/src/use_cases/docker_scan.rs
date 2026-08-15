use std::sync::Arc;

use chrono::Utc;
use hangar_domain::docker_registry::{Digest, DockerGrantedScope, DockerImageName, DockerManifestRepositoryPort, DockerTokenIssuerPort};
use hangar_domain::docker_scan::{DockerImageScanRepositoryPort, DockerImageScanResult, DockerImageScannerPort};
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use uuid::Uuid;

use crate::error::ApplicationError;

/// A real Trivy scan can take real time, so a page view must never wait on it — this always writes a new row, and callers read the last one back via `GetDockerImageScanResultUseCase`.
pub struct ScanDockerImageUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    repositories: Arc<dyn PackageRepositoryQueryPort>,
    token_issuer: Arc<dyn DockerTokenIssuerPort>,
    scanner: Arc<dyn DockerImageScannerPort>,
    results: Arc<dyn DockerImageScanRepositoryPort>,
}

impl ScanDockerImageUseCase {
    pub fn new(
        manifests: Arc<dyn DockerManifestRepositoryPort>,
        repositories: Arc<dyn PackageRepositoryQueryPort>,
        token_issuer: Arc<dyn DockerTokenIssuerPort>,
        scanner: Arc<dyn DockerImageScannerPort>,
        results: Arc<dyn DockerImageScanRepositoryPort>,
    ) -> Self {
        Self { manifests, repositories, token_issuer, scanner, results }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str, triggered_by: Uuid) -> Result<DockerImageScanResult, ApplicationError> {
        let repository = self.repositories.find_by_id(repository_id).await?.ok_or(ApplicationError::DockerManifestNotFound)?;
        let manifest = self.manifests.find_manifest_by_tag(repository_id, image_name, tag).await?.ok_or(ApplicationError::DockerManifestNotFound)?;

        // A manifest list has nothing to scan itself — pick a concrete linux-platform member.
        let (scan_reference, platform) = if manifest.media_type.is_index() {
            match pick_linux_member(&manifest.body) {
                Some((digest, platform)) => (digest.as_str().to_string(), Some(platform)),
                None => return Err(ApplicationError::DockerManifestNotFound),
            }
        } else {
            (tag.to_string(), None)
        };

        let scope = DockerGrantedScope {
            resource_type: "repository".to_string(),
            name: format!("{}/{}", repository.name, image_name.as_str()),
            actions: vec!["pull".to_string()],
            granted_repository_id: Some(repository.id),
        };
        // Internal system-initiated pull — the scanner fetching the image it's about to scan.
        let token = self.token_issuer.issue(triggered_by, repository.organization_id, false, Some(scope))?;

        let vulnerabilities = self.scanner.scan(&repository.name, image_name.as_str(), &scan_reference, platform.as_deref(), &token).await?;

        let result = DockerImageScanResult { id: Uuid::new_v4(), docker_manifest_id: manifest.id, scanned_at: Utc::now(), vulnerabilities };
        self.results.save(&result).await?;
        Ok(result)
    }
}

/// Never triggers a fresh scan itself.
pub struct GetDockerImageScanResultUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
    results: Arc<dyn DockerImageScanRepositoryPort>,
}

impl GetDockerImageScanResultUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>, results: Arc<dyn DockerImageScanRepositoryPort>) -> Self {
        Self { manifests, results }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str) -> Result<Option<DockerImageScanResult>, ApplicationError> {
        let Some(manifest) = self.manifests.find_manifest_by_tag(repository_id, image_name, tag).await? else { return Ok(None) };
        Ok(self.results.find_latest_for_manifest(manifest.id).await?)
    }
}

/// Skips members missing a platform (e.g. attestation manifests) rather than erroring.
fn pick_linux_member(index_body: &[u8]) -> Option<(Digest, String)> {
    let value: serde_json::Value = serde_json::from_slice(index_body).ok()?;
    let members = value.get("manifests")?.as_array()?;
    for member in members {
        let Some(platform) = member.get("platform") else { continue };
        let Some(os) = platform.get("os").and_then(|v| v.as_str()) else { continue };
        if os != "linux" {
            continue;
        }
        let Some(arch) = platform.get("architecture").and_then(|v| v.as_str()) else { continue };
        let Some(digest_str) = member.get("digest").and_then(|v| v.as_str()) else { continue };
        let Ok(digest) = Digest::parse(digest_str) else { continue };
        return Some((digest, format!("{os}/{arch}")));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerImageScanResults, FakeDockerImageScanner, FakeDockerManifestRepository, FakeDockerTokenIssuer, FakeRepositories};
    use hangar_domain::docker_registry::{DockerManifest, DockerMediaType};
    use hangar_domain::docker_scan::DockerVulnerability;
    use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};

    fn sample_vulnerability() -> DockerVulnerability {
        DockerVulnerability {
            id: "CVE-2022-4450".to_string(),
            package_name: "libcrypto1.1".to_string(),
            installed_version: "1.1.1n-r0".to_string(),
            fixed_version: Some("1.1.1t-r0".to_string()),
            severity: "HIGH".to_string(),
            title: Some("openssl: double free after calling PEM_read_bio_ex".to_string()),
            primary_url: Some("https://avd.aquasec.com/nvd/cve-2022-4450".to_string()),
        }
    }

    struct Harness {
        manifests: Arc<FakeDockerManifestRepository>,
        repositories: Arc<FakeRepositories>,
        token_issuer: Arc<FakeDockerTokenIssuer>,
        scanner: Arc<FakeDockerImageScanner>,
        results: Arc<FakeDockerImageScanResults>,
        repository_id: Uuid,
        image_name: DockerImageName,
    }

    impl Harness {
        fn new(vulnerabilities: Vec<DockerVulnerability>) -> Self {
            let repository_id = Uuid::new_v4();
            let repositories = Arc::new(FakeRepositories::new());
            repositories.insert(PackageRepositorySummary {
                id: repository_id,
                organization_id: Uuid::new_v4(),
                name: "myrepo".to_string(),
                format: RepositoryFormat::Docker,
                repo_type: RepositoryType::Hosted,
                remote_url: None,
                remote_username: None,
                remote_password: None,
                quota_bytes: None, retention_keep_last_n: None, group_members: vec![],
            });
            Self {
                manifests: Arc::new(FakeDockerManifestRepository::new()),
                repositories,
                token_issuer: Arc::new(FakeDockerTokenIssuer::new()),
                scanner: Arc::new(FakeDockerImageScanner::new(vulnerabilities)),
                results: Arc::new(FakeDockerImageScanResults::new()),
                repository_id,
                image_name: DockerImageName::parse("myimage").unwrap(),
            }
        }

        fn seed_manifest(&self, media_type: DockerMediaType, body: &[u8], tag: &str) -> Uuid {
            let manifest_id = Uuid::new_v4();
            let manifest = DockerManifest {
                id: manifest_id,
                package_repository_id: self.repository_id,
                image_name: self.image_name.clone(),
                digest: Digest::of(body),
                media_type,
                body: body.to_vec(),
                created_at: Utc::now(),
            };
            self.manifests.manifests.lock().unwrap().insert(manifest_id, manifest);
            self.manifests.tags.lock().unwrap().insert((self.repository_id, self.image_name.as_str().to_string(), tag.to_string()), manifest_id);
            manifest_id
        }

        fn use_case(&self) -> ScanDockerImageUseCase {
            ScanDockerImageUseCase::new(self.manifests.clone(), self.repositories.clone(), self.token_issuer.clone(), self.scanner.clone(), self.results.clone())
        }
    }

    #[tokio::test]
    async fn scans_a_single_platform_manifest_by_tag_and_persists_the_result() {
        let h = Harness::new(vec![sample_vulnerability()]);
        let manifest_id = h.seed_manifest(DockerMediaType::DockerV2Manifest, b"{}", "latest");
        let triggered_by = Uuid::new_v4();

        let result = h.use_case().execute(h.repository_id, &h.image_name, "latest", triggered_by).await.unwrap();

        assert_eq!(result.docker_manifest_id, manifest_id);
        assert_eq!(result.vulnerabilities.len(), 1);
        assert_eq!(result.vulnerabilities[0].id, "CVE-2022-4450");
        assert_eq!(h.results.saved.lock().unwrap().len(), 1);

        let (repo_name, image_name, reference, platform, token) = h.scanner.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(repo_name, "myrepo");
        assert_eq!(image_name, "myimage");
        assert_eq!(reference, "latest");
        assert_eq!(platform, None);
        assert_eq!(token, "fake-registry-token");

        let (issued_for, scope) = h.token_issuer.issued.lock().unwrap()[0].clone();
        assert_eq!(issued_for, triggered_by);
        assert_eq!(scope.unwrap().actions, vec!["pull".to_string()]);
    }

    #[tokio::test]
    async fn scans_the_first_linux_member_of_a_manifest_list_by_digest() {
        let h = Harness::new(vec![]);
        let member_digest = Digest::of(b"linux-arm64-manifest-bytes");
        let unknown_digest = Digest::of(b"attestation-manifest-bytes");
        let index_body = serde_json::json!({
            "manifests": [
                { "digest": unknown_digest.as_str(), "platform": { "architecture": "unknown", "os": "unknown" } },
                { "digest": member_digest.as_str(), "platform": { "architecture": "arm64", "os": "linux" } },
            ]
        });
        h.seed_manifest(DockerMediaType::OciIndex, index_body.to_string().as_bytes(), "latest");

        h.use_case().execute(h.repository_id, &h.image_name, "latest", Uuid::new_v4()).await.unwrap();

        let (_, _, reference, platform, _) = h.scanner.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(reference, member_digest.as_str());
        assert_eq!(platform, Some("linux/arm64".to_string()));
    }

    #[tokio::test]
    async fn scanning_an_unknown_tag_fails_with_manifest_not_found() {
        let h = Harness::new(vec![]);
        let err = h.use_case().execute(h.repository_id, &h.image_name, "latest", Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::DockerManifestNotFound));
    }

    #[tokio::test]
    async fn scanning_an_unknown_repository_fails_with_manifest_not_found() {
        let h = Harness::new(vec![]);
        let err = h.use_case().execute(Uuid::new_v4(), &h.image_name, "latest", Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::DockerManifestNotFound));
    }

    #[tokio::test]
    async fn get_docker_image_scan_result_returns_none_when_never_scanned() {
        let h = Harness::new(vec![]);
        h.seed_manifest(DockerMediaType::DockerV2Manifest, b"{}", "latest");
        let use_case = GetDockerImageScanResultUseCase::new(h.manifests.clone(), h.results.clone());

        let result = use_case.execute(h.repository_id, &h.image_name, "latest").await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_docker_image_scan_result_returns_the_last_scan() {
        let h = Harness::new(vec![sample_vulnerability()]);
        h.seed_manifest(DockerMediaType::DockerV2Manifest, b"{}", "latest");
        h.use_case().execute(h.repository_id, &h.image_name, "latest", Uuid::new_v4()).await.unwrap();

        let use_case = GetDockerImageScanResultUseCase::new(h.manifests.clone(), h.results.clone());
        let result = use_case.execute(h.repository_id, &h.image_name, "latest").await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().vulnerabilities.len(), 1);
    }
}
