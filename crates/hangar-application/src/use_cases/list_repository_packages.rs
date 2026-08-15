use std::sync::Arc;

use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::DockerManifestRepositoryPort;
use hangar_domain::npm_package::NpmPackageRepositoryPort;
use hangar_domain::package_repository::RepositoryFormat;
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct NpmPackageTreeVersion {
    pub version: String,
    pub published_at: DateTime<Utc>,
    pub size_bytes: i64,
    pub deprecated: bool,
}

pub struct NpmPackageTreeEntry {
    pub name: String,
    pub versions: Vec<NpmPackageTreeVersion>,
}

pub struct DockerImageTreeEntry {
    pub image_name: String,
    pub tags: Vec<String>,
}

pub enum RepositoryPackageTree {
    Npm(Vec<NpmPackageTreeEntry>),
    Docker(Vec<DockerImageTreeEntry>),
}

pub struct ListRepositoryPackagesUseCase {
    npm_packages: Arc<dyn NpmPackageRepositoryPort>,
    docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl ListRepositoryPackagesUseCase {
    pub fn new(
        npm_packages: Arc<dyn NpmPackageRepositoryPort>,
        docker_manifests: Arc<dyn DockerManifestRepositoryPort>,
    ) -> Self {
        Self { npm_packages, docker_manifests }
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
        let mut versions_by_package: std::collections::HashMap<Uuid, Vec<_>> = std::collections::HashMap::new();
        for v in all_versions {
            versions_by_package.entry(v.npm_package_id).or_default().push(v);
        }

        let mut entries = Vec::with_capacity(packages.len());
        for package in packages {
            let mut versions = versions_by_package.remove(&package.id).unwrap_or_default();
            versions.sort_by_key(|v| std::cmp::Reverse(v.published_at));
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
            });
        }
        Ok(entries)
    }

    async fn list_docker(&self, repository_id: Uuid) -> Result<Vec<DockerImageTreeEntry>, ApplicationError> {
        let pairs = self.docker_manifests.list_all_tags_for_repository(repository_id).await?;
        let mut tags_by_image: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (image_name, tag) in pairs {
            tags_by_image.entry(image_name.as_str().to_string()).or_default().push(tag);
        }

        let mut sorted_names: Vec<String> = tags_by_image.keys().cloned().collect();
        sorted_names.sort();
        let mut entries = Vec::with_capacity(sorted_names.len());
        for image_name in sorted_names {
            let mut tags = tags_by_image.remove(&image_name).unwrap_or_default();
            tags.sort();
            entries.push(DockerImageTreeEntry { image_name, tags });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::FakeDockerManifestRepository;
    use crate::use_cases::npm_test_support::FakePackages;
    use chrono::Duration;
    use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerMediaType};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

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

        let use_case = ListRepositoryPackagesUseCase::new(packages, Arc::new(FakeDockerManifestRepository::new()));
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

        let use_case = ListRepositoryPackagesUseCase::new(Arc::new(FakePackages::new()), manifests);
        let tree = use_case.execute(repository_id, RepositoryFormat::Docker).await.unwrap();

        let RepositoryPackageTree::Docker(entries) = tree else { panic!("expected a docker tree") };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].image_name, "my-app");
        assert_eq!(entries[0].tags, vec!["1.0.0".to_string(), "latest".to_string()]);
    }
}
