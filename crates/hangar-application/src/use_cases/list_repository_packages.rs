use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::DockerManifestRepositoryPort;
use hangar_domain::docker_scan::DockerImageScanRepositoryPort;
use hangar_domain::npm_audit::DependencyAuditRepositoryPort;
use hangar_domain::npm_package::NpmPackageRepositoryPort;
use hangar_domain::package_repository::RepositoryFormat;
use uuid::Uuid;

use crate::error::ApplicationError;

/// Vulnerability counts from the latest scan/audit, bucketed to the 4 severities the UI
/// surfaces as colored circles. "unknown"/other severities are intentionally dropped rather
/// than shown — they're rarely actionable and would just add a 5th, noisier circle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VulnerabilitySummary {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

impl VulnerabilitySummary {
    /// Case-insensitive; treats npm's "moderate" the same as Trivy's "medium" — same tier, different vocabulary.
    fn count<'a>(severities: impl Iterator<Item = &'a str>) -> Self {
        let mut summary = Self::default();
        for raw in severities {
            match raw.to_ascii_lowercase().as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" | "moderate" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => {}
            }
        }
        summary
    }
}

pub struct NpmPackageTreeVersion {
    pub version: String,
    pub published_at: DateTime<Utc>,
    pub size_bytes: i64,
    pub deprecated: bool,
}

pub struct NpmPackageTreeEntry {
    pub name: String,
    pub versions: Vec<NpmPackageTreeVersion>,
    /// From the most-recently-published version's dependency audit — absent (all zeros) if that version was never audited.
    pub vulnerability_summary: VulnerabilitySummary,
}

pub struct DockerImageTreeEntry {
    pub image_name: String,
    pub tags: Vec<String>,
    /// From the most-recently-updated tag's scan — absent (all zeros) if that manifest was never scanned.
    pub vulnerability_summary: VulnerabilitySummary,
}

pub enum RepositoryPackageTree {
    Npm(Vec<NpmPackageTreeEntry>),
    Docker(Vec<DockerImageTreeEntry>),
}

pub struct ListRepositoryPackagesUseCase {
    npm_packages: Arc<dyn NpmPackageRepositoryPort>,
    npm_dependency_audits: Arc<dyn DependencyAuditRepositoryPort>,
    docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
    docker_image_scans: Arc<dyn DockerImageScanRepositoryPort>,
}

impl ListRepositoryPackagesUseCase {
    pub fn new(
        npm_packages: Arc<dyn NpmPackageRepositoryPort>,
        npm_dependency_audits: Arc<dyn DependencyAuditRepositoryPort>,
        docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
        docker_image_scans: Arc<dyn DockerImageScanRepositoryPort>,
    ) -> Self {
        Self { npm_packages, npm_dependency_audits, docker_manifests, docker_image_scans }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        format: RepositoryFormat,
    ) -> Result<RepositoryPackageTree, ApplicationError> {
        match format {
            RepositoryFormat::Npm => Ok(RepositoryPackageTree::Npm(self.list_npm(repository_id).await?)),
            RepositoryFormat::Docker => Ok(RepositoryPackageTree::Docker(self.list_docker(repository_id).await?)),
        }
    }

    async fn list_npm(&self, repository_id: Uuid) -> Result<Vec<NpmPackageTreeEntry>, ApplicationError> {
        let packages = self.npm_packages.search(repository_id, "", i64::MAX).await?;
        let package_ids: Vec<Uuid> = packages.iter().map(|p| p.id).collect();
        let all_versions = self.npm_packages.list_versions_for_packages(&package_ids).await?;
        let mut versions_by_package: HashMap<Uuid, Vec<_>> = HashMap::new();
        for v in all_versions {
            versions_by_package.entry(v.npm_package_id).or_default().push(v);
        }

        // Snapshot each package's newest version id *before* consuming the map below — that's
        // the version whose audit results the summary circle is drawn from.
        let mut latest_version_id_by_package: HashMap<Uuid, Uuid> = HashMap::new();
        for (package_id, versions) in &mut versions_by_package {
            versions.sort_by_key(|v| std::cmp::Reverse(v.published_at));
            if let Some(latest) = versions.first() {
                latest_version_id_by_package.insert(*package_id, latest.id);
            }
        }
        let latest_version_ids: Vec<Uuid> = latest_version_id_by_package.values().copied().collect();
        let audits = self.npm_dependency_audits.find_latest_for_versions(&latest_version_ids).await?;
        let audit_by_version: HashMap<Uuid, _> = audits.into_iter().map(|a| (a.npm_package_version_id, a)).collect();

        let mut entries = Vec::with_capacity(packages.len());
        for package in packages {
            let versions = versions_by_package.remove(&package.id).unwrap_or_default();
            let vulnerability_summary = latest_version_id_by_package
                .get(&package.id)
                .and_then(|version_id| audit_by_version.get(version_id))
                .map(|audit| VulnerabilitySummary::count(audit.findings.iter().map(|f| f.advisory.severity.as_str())))
                .unwrap_or_default();
            entries.push(NpmPackageTreeEntry {
                name: package.name.as_str().to_string(),
                versions: versions
                    .into_iter()
                    .map(|v| NpmPackageTreeVersion {
                        version: v.version.as_str(),
                        published_at: v.published_at,
                        size_bytes: v.tarball_size_bytes,
                        deprecated: v.deprecated,
                    })
                    .collect(),
                vulnerability_summary,
            });
        }
        Ok(entries)
    }

    async fn list_docker(&self, repository_id: Uuid) -> Result<Vec<DockerImageTreeEntry>, ApplicationError> {
        let pairs = self.docker_manifests.list_all_tags_for_repository(repository_id).await?;
        let mut tags_by_image: HashMap<String, Vec<String>> = HashMap::new();
        for (image_name, tag) in pairs {
            tags_by_image.entry(image_name.as_str().to_string()).or_default().push(tag);
        }

        let latest_manifests = self.docker_manifests.list_latest_manifest_id_per_image(repository_id).await?;
        let latest_manifest_id_by_image: HashMap<String, Uuid> =
            latest_manifests.iter().map(|(name, id)| (name.as_str().to_string(), *id)).collect();
        let manifest_ids: Vec<Uuid> = latest_manifests.into_iter().map(|(_, id)| id).collect();
        let scans = self.docker_image_scans.find_latest_for_manifests(&manifest_ids).await?;
        let scan_by_manifest: HashMap<Uuid, _> = scans.into_iter().map(|s| (s.docker_manifest_id, s)).collect();

        let mut sorted_names: Vec<String> = tags_by_image.keys().cloned().collect();
        sorted_names.sort();
        let mut entries = Vec::with_capacity(sorted_names.len());
        for image_name in sorted_names {
            let mut tags = tags_by_image.remove(&image_name).unwrap_or_default();
            tags.sort();
            let vulnerability_summary = latest_manifest_id_by_image
                .get(&image_name)
                .and_then(|manifest_id| scan_by_manifest.get(manifest_id))
                .map(|scan| VulnerabilitySummary::count(scan.vulnerabilities.iter().map(|v| v.severity.as_str())))
                .unwrap_or_default();
            entries.push(DockerImageTreeEntry { image_name, tags, vulnerability_summary });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerImageScanResults, FakeDockerManifestRepository};
    use crate::use_cases::npm_test_support::{FakeDependencyAuditResults, FakePackages};
    use chrono::Duration;
    use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerMediaType};
    use hangar_domain::docker_scan::{DockerImageScanResult, DockerVulnerability};
    use hangar_domain::npm_audit::{DependencyAuditFinding, DependencyAuditResult, NpmAdvisory};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

    fn build_use_case(
        packages: Arc<FakePackages>,
        audits: Arc<FakeDependencyAuditResults>,
        manifests: Arc<FakeDockerManifestRepository>,
        scans: Arc<FakeDockerImageScanResults>,
    ) -> ListRepositoryPackagesUseCase {
        ListRepositoryPackagesUseCase::new(packages, audits, manifests, scans)
    }

    fn sample_npm_package(repository_id: Uuid, name: &str) -> NpmPackage {
        NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: NpmPackageName::parse(name).unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        }
    }

    fn sample_npm_version(npm_package_id: Uuid, version: &str) -> NpmPackageVersion {
        NpmPackageVersion {
            id: Uuid::new_v4(),
            npm_package_id,
            version: NpmVersion::parse(version).unwrap(),
            manifest: serde_json::json!({}),
            shasum: "shasum".to_string(),
            integrity: "integrity".to_string(),
            tarball_storage_key: "key".to_string(),
            tarball_size_bytes: 1234,
            deprecated: false,
            deprecated_message: None,
            published_by: None,
            published_at: Utc::now(),
            origin: NpmPackageOrigin::Local,
        }
    }

    fn docker_manifest(repository_id: Uuid, name: &DockerImageName) -> DockerManifest {
        DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: name.clone(),
            digest: Digest::of(name.as_str().as_bytes()),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn lists_npm_packages_with_their_versions_newest_first() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let package = sample_npm_package(repository_id, "left-pad");
        packages.create_package(&package).await.unwrap();
        let mut older = sample_npm_version(package.id, "1.0.0");
        older.published_at = Utc::now() - Duration::days(1);
        let newer = sample_npm_version(package.id, "1.1.0");
        packages.insert_version(&older).await.unwrap();
        packages.insert_version(&newer).await.unwrap();

        let use_case = build_use_case(
            packages,
            Arc::new(FakeDependencyAuditResults::new()),
            Arc::new(FakeDockerManifestRepository::new()),
            Arc::new(FakeDockerImageScanResults::new()),
        );
        let tree = use_case.execute(repository_id, RepositoryFormat::Npm).await.unwrap();

        let RepositoryPackageTree::Npm(entries) = tree else { panic!("expected an npm tree") };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "left-pad");
        assert_eq!(entries[0].versions.iter().map(|v| v.version.as_str()).collect::<Vec<_>>(), vec!["1.1.0", "1.0.0"]);
    }

    #[tokio::test]
    async fn lists_docker_images_with_their_tags_deduplicated_and_sorted() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("my-app").unwrap();
        let manifest = docker_manifest(repository_id, &name);
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        // Two tags on the SAME image must still surface it only once.
        manifests.set_tag(repository_id, &name, "latest", manifest.id).await.unwrap();
        manifests.set_tag(repository_id, &name, "1.0.0", manifest.id).await.unwrap();

        let use_case = build_use_case(
            Arc::new(FakePackages::new()),
            Arc::new(FakeDependencyAuditResults::new()),
            manifests,
            Arc::new(FakeDockerImageScanResults::new()),
        );
        let tree = use_case.execute(repository_id, RepositoryFormat::Docker).await.unwrap();

        let RepositoryPackageTree::Docker(entries) = tree else { panic!("expected a docker tree") };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].image_name, "my-app");
        assert_eq!(entries[0].tags, vec!["1.0.0".to_string(), "latest".to_string()]);
    }

    fn vuln(severity: &str) -> DockerVulnerability {
        DockerVulnerability {
            id: format!("CVE-{severity}"),
            package_name: "libfoo".to_string(),
            installed_version: "1.0.0".to_string(),
            fixed_version: None,
            severity: severity.to_string(),
            title: None,
            primary_url: None,
        }
    }

    fn finding(severity: &str) -> DependencyAuditFinding {
        DependencyAuditFinding {
            dependency_name: "left-pad".to_string(),
            dependency_version: "1.0.0".to_string(),
            advisory: NpmAdvisory {
                id: 1,
                url: "https://example.com".to_string(),
                title: "x".to_string(),
                severity: severity.to_string(),
                vulnerable_versions: "*".to_string(),
                cwe: vec![],
                cvss_score: None,
            },
        }
    }

    #[tokio::test]
    async fn docker_image_summary_counts_the_latest_tags_scan_by_severity_and_drops_unknown() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let scans = Arc::new(FakeDockerImageScanResults::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("my-app").unwrap();
        let manifest = docker_manifest(repository_id, &name);
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", manifest.id).await.unwrap();
        scans
            .save(&DockerImageScanResult {
                id: Uuid::new_v4(),
                docker_manifest_id: manifest.id,
                scanned_at: Utc::now(),
                vulnerabilities: vec![vuln("CRITICAL"), vuln("HIGH"), vuln("HIGH"), vuln("low"), vuln("UNKNOWN")],
            })
            .await
            .unwrap();

        let use_case = build_use_case(Arc::new(FakePackages::new()), Arc::new(FakeDependencyAuditResults::new()), manifests, scans);
        let tree = use_case.execute(repository_id, RepositoryFormat::Docker).await.unwrap();

        let RepositoryPackageTree::Docker(entries) = tree else { panic!("expected a docker tree") };
        let summary = &entries[0].vulnerability_summary;
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 1);
    }

    #[tokio::test]
    async fn docker_image_summary_follows_the_most_recently_updated_tag_not_an_older_one() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let scans = Arc::new(FakeDockerImageScanResults::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("my-app").unwrap();
        let old_manifest = docker_manifest(repository_id, &name);
        let mut new_manifest = docker_manifest(repository_id, &name);
        new_manifest.digest = Digest::of(b"a different manifest body");
        manifests.insert_manifest(&old_manifest, &[]).await.unwrap();
        manifests.insert_manifest(&new_manifest, &[]).await.unwrap();
        // "1.0.0" is set first (older), "latest" repointed afterwards (more recent) — the
        // summary must come from "latest"'s manifest, not "1.0.0"'s.
        manifests.set_tag(repository_id, &name, "1.0.0", old_manifest.id).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", new_manifest.id).await.unwrap();
        scans
            .save(&DockerImageScanResult { id: Uuid::new_v4(), docker_manifest_id: old_manifest.id, scanned_at: Utc::now(), vulnerabilities: vec![vuln("CRITICAL")] })
            .await
            .unwrap();
        scans
            .save(&DockerImageScanResult { id: Uuid::new_v4(), docker_manifest_id: new_manifest.id, scanned_at: Utc::now(), vulnerabilities: vec![vuln("LOW")] })
            .await
            .unwrap();

        let use_case = build_use_case(Arc::new(FakePackages::new()), Arc::new(FakeDependencyAuditResults::new()), manifests, scans);
        let tree = use_case.execute(repository_id, RepositoryFormat::Docker).await.unwrap();

        let RepositoryPackageTree::Docker(entries) = tree else { panic!("expected a docker tree") };
        let summary = &entries[0].vulnerability_summary;
        assert_eq!(summary.critical, 0, "must not pick up the older tag's scan");
        assert_eq!(summary.low, 1);
    }

    #[tokio::test]
    async fn docker_image_never_scanned_gets_an_all_zero_summary() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("my-app").unwrap();
        let manifest = docker_manifest(repository_id, &name);
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", manifest.id).await.unwrap();

        let use_case = build_use_case(
            Arc::new(FakePackages::new()),
            Arc::new(FakeDependencyAuditResults::new()),
            manifests,
            Arc::new(FakeDockerImageScanResults::new()),
        );
        let tree = use_case.execute(repository_id, RepositoryFormat::Docker).await.unwrap();

        let RepositoryPackageTree::Docker(entries) = tree else { panic!("expected a docker tree") };
        assert_eq!(entries[0].vulnerability_summary, VulnerabilitySummary::default());
    }

    #[tokio::test]
    async fn npm_package_summary_comes_from_the_newest_versions_audit_not_an_older_one() {
        let packages = Arc::new(FakePackages::new());
        let audits = Arc::new(FakeDependencyAuditResults::new());
        let repository_id = Uuid::new_v4();
        let package = sample_npm_package(repository_id, "left-pad");
        packages.create_package(&package).await.unwrap();
        let mut older = sample_npm_version(package.id, "1.0.0");
        older.published_at = Utc::now() - Duration::days(1);
        let newer = sample_npm_version(package.id, "1.1.0");
        packages.insert_version(&older).await.unwrap();
        packages.insert_version(&newer).await.unwrap();
        audits
            .save(&DependencyAuditResult { id: Uuid::new_v4(), npm_package_version_id: older.id, scanned_at: Utc::now(), packages_scanned: 1, truncated: false, findings: vec![finding("critical")] })
            .await
            .unwrap();
        audits
            .save(&DependencyAuditResult {
                id: Uuid::new_v4(),
                npm_package_version_id: newer.id,
                scanned_at: Utc::now(),
                packages_scanned: 1,
                truncated: false,
                findings: vec![finding("moderate"), finding("moderate")],
            })
            .await
            .unwrap();

        let use_case = build_use_case(packages, audits, Arc::new(FakeDockerManifestRepository::new()), Arc::new(FakeDockerImageScanResults::new()));
        let tree = use_case.execute(repository_id, RepositoryFormat::Npm).await.unwrap();

        let RepositoryPackageTree::Npm(entries) = tree else { panic!("expected an npm tree") };
        let summary = &entries[0].vulnerability_summary;
        assert_eq!(summary.critical, 0, "must not pick up the older version's audit");
        assert_eq!(summary.medium, 2, "npm's \"moderate\" must bucket into the same tier as Trivy's \"medium\"");
    }

    #[tokio::test]
    async fn npm_package_never_audited_gets_an_all_zero_summary() {
        let packages = Arc::new(FakePackages::new());
        let repository_id = Uuid::new_v4();
        let package = sample_npm_package(repository_id, "left-pad");
        packages.create_package(&package).await.unwrap();
        packages.insert_version(&sample_npm_version(package.id, "1.0.0")).await.unwrap();

        let use_case = build_use_case(packages, Arc::new(FakeDependencyAuditResults::new()), Arc::new(FakeDockerManifestRepository::new()), Arc::new(FakeDockerImageScanResults::new()));
        let tree = use_case.execute(repository_id, RepositoryFormat::Npm).await.unwrap();

        let RepositoryPackageTree::Npm(entries) = tree else { panic!("expected an npm tree") };
        assert_eq!(entries[0].vulnerability_summary, VulnerabilitySummary::default());
    }
}
