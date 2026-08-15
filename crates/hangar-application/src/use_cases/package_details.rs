use std::sync::Arc;

use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::{DockerImageName, DockerManifestRepositoryPort};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct NpmVersionDetail {
    pub version: String,
    pub published_at: DateTime<Utc>,
    pub size_bytes: i64,
    pub deprecated: bool,
    pub deprecated_message: Option<String>,
    pub shasum: String,
}

pub struct NpmDistTagDetail {
    pub tag: String,
    pub version: String,
}

pub struct NpmPackageDetails {
    pub name: String,
    pub versions: Vec<NpmVersionDetail>,
    pub dist_tags: Vec<NpmDistTagDetail>,
}

/// `None` when the package doesn't exist, including "existed but was fully unpublished".
pub struct GetNpmPackageDetailsUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
}

impl GetNpmPackageDetailsUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>) -> Self {
        Self { packages }
    }

    pub async fn execute(&self, repository_id: Uuid, name: &NpmPackageName) -> Result<Option<NpmPackageDetails>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else {
            return Ok(None);
        };
        let mut versions = self.packages.list_versions(package.id).await?;
        versions.sort_by_key(|v| std::cmp::Reverse(v.published_at));
        let dist_tags = self.packages.list_dist_tags(package.id).await?;
        Ok(Some(NpmPackageDetails {
            name: name.as_str().to_string(),
            versions: versions
                .into_iter()
                .map(|v| NpmVersionDetail {
                    version: v.version.as_str(),
                    published_at: v.published_at,
                    size_bytes: v.tarball_size_bytes,
                    deprecated: v.deprecated,
                    deprecated_message: v.deprecated_message,
                    shasum: v.shasum,
                })
                .collect(),
            dist_tags: dist_tags.into_iter().map(|t| NpmDistTagDetail { tag: t.tag, version: t.version.as_str() }).collect(),
        }))
    }
}

pub struct DockerTagDetail {
    pub tag: String,
    pub digest: String,
    pub media_type: String,
    pub created_at: DateTime<Utc>,
}

pub struct DockerImageDetails {
    pub image_name: String,
    pub tags: Vec<DockerTagDetail>,
}

/// A tag whose manifest disappeared between listing and resolving is silently dropped.
pub struct GetDockerImageDetailsUseCase {
    manifests: Arc<dyn DockerManifestRepositoryPort>,
}

impl GetDockerImageDetailsUseCase {
    pub fn new(manifests: Arc<dyn DockerManifestRepositoryPort>) -> Self {
        Self { manifests }
    }

    pub async fn execute(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<DockerImageDetails, ApplicationError> {
        let summaries = self.manifests.list_tag_manifest_summaries(repository_id, image_name).await?;
        let tags = summaries
            .into_iter()
            .map(|(tag, digest, media_type, created_at)| DockerTagDetail { tag, digest: digest.as_str().to_string(), media_type: media_type.as_str().to_string(), created_at })
            .collect();
        Ok(DockerImageDetails { image_name: image_name.as_str().to_string(), tags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::FakeDockerManifestRepository;
    use crate::use_cases::npm_test_support::FakePackages;
    use chrono::Duration;
    use hangar_domain::docker_registry::{Digest, DockerManifest, DockerMediaType};
    use hangar_domain::npm_package::{NpmPackage, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

    #[tokio::test]
    async fn returns_none_for_an_unknown_npm_package() {
        let use_case = GetNpmPackageDetailsUseCase::new(Arc::new(FakePackages::new()));
        let result = use_case.execute(Uuid::new_v4(), &NpmPackageName::parse("left-pad").unwrap()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn returns_versions_newest_first_and_dist_tags() {
        let packages = Arc::new(FakePackages::new());
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
        let v1 = NpmVersion::parse("1.0.0").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: v1.clone(),
                manifest: serde_json::json!({}),
                shasum: "s1".to_string(),
                integrity: "i1".to_string(),
                tarball_storage_key: "k1".to_string(),
                tarball_size_bytes: 10,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: Utc::now() - Duration::days(1),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: v2.clone(),
                manifest: serde_json::json!({}),
                shasum: "s2".to_string(),
                integrity: "i2".to_string(),
                tarball_storage_key: "k2".to_string(),
                tarball_size_bytes: 20,
                deprecated: true,
                deprecated_message: Some("use v3 instead".to_string()),
                published_by: None,
                published_at: Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        packages.set_dist_tag(package.id, "latest", &v2).await.unwrap();

        let use_case = GetNpmPackageDetailsUseCase::new(packages);
        let details = use_case.execute(repository_id, &name).await.unwrap().unwrap();

        assert_eq!(details.name, "left-pad");
        assert_eq!(details.versions.iter().map(|v| v.version.as_str()).collect::<Vec<_>>(), vec!["2.0.0", "1.0.0"]);
        assert!(details.versions[0].deprecated);
        assert_eq!(details.versions[0].deprecated_message.as_deref(), Some("use v3 instead"));
        assert_eq!(details.dist_tags.len(), 1);
        assert_eq!(details.dist_tags[0].tag, "latest");
        assert_eq!(details.dist_tags[0].version, "2.0.0");
    }

    #[tokio::test]
    async fn resolves_each_tag_to_its_manifests_digest_and_media_type() {
        let manifests = Arc::new(FakeDockerManifestRepository::new());
        let repository_id = Uuid::new_v4();
        let name = DockerImageName::parse("my-app").unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: name.clone(),
            digest: Digest::of(b"{}"),
            media_type: DockerMediaType::OciManifest,
            body: b"{}".to_vec(),
            created_at: Utc::now(),
        };
        manifests.insert_manifest(&manifest, &[]).await.unwrap();
        manifests.set_tag(repository_id, &name, "latest", manifest.id).await.unwrap();

        let use_case = GetDockerImageDetailsUseCase::new(manifests);
        let details = use_case.execute(repository_id, &name).await.unwrap();

        assert_eq!(details.image_name, "my-app");
        assert_eq!(details.tags.len(), 1);
        assert_eq!(details.tags[0].tag, "latest");
        assert_eq!(details.tags[0].digest, manifest.digest.as_str());
        assert_eq!(details.tags[0].media_type, "application/vnd.oci.image.manifest.v1+json");
    }
}
