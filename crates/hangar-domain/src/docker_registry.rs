use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_core::stream::BoxStream;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

/// A boxed stream of chunks, for serving a large blob without buffering it fully in memory.
pub type ByteStream = BoxStream<'static, Result<Bytes, DomainError>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest(String);

impl Digest {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let Some(hex) = raw.strip_prefix("sha256:") else {
            return Err(DomainError::Validation(format!("unsupported digest algorithm: {raw}")));
        };
        let valid = hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if valid {
            Ok(Self(raw.to_string()))
        } else {
            Err(DomainError::Validation(format!("invalid sha256 digest: {raw}")))
        }
    }

    /// The real digest of `bytes` — never trust a client-declared digest instead.
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest as _, Sha256};
        let hash = Sha256::digest(bytes);
        Self(format!("sha256:{}", hex::encode(hash)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DockerImageName(String);

impl DockerImageName {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.is_empty() {
            return Err(DomainError::Validation("image name must not be empty".into()));
        }
        for segment in raw.split('/') {
            let valid_segment = !segment.is_empty()
                && segment.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && segment.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-');
            if !valid_segment {
                return Err(DomainError::Validation(format!("invalid image name segment: {segment:?} in {raw:?}")));
            }
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DockerMediaType {
    DockerV2Manifest,
    OciManifest,
    OciIndex,
}

impl DockerMediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DockerMediaType::DockerV2Manifest => "application/vnd.docker.distribution.manifest.v2+json",
            DockerMediaType::OciManifest => "application/vnd.oci.image.manifest.v1+json",
            DockerMediaType::OciIndex => "application/vnd.oci.image.index.v1+json",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "application/vnd.docker.distribution.manifest.v2+json" => Ok(DockerMediaType::DockerV2Manifest),
            "application/vnd.oci.image.manifest.v1+json" => Ok(DockerMediaType::OciManifest),
            "application/vnd.oci.image.index.v1+json" | "application/vnd.docker.distribution.manifest.list.v2+json" => {
                Ok(DockerMediaType::OciIndex)
            }
            other => Err(DomainError::Validation(format!("unsupported manifest media type: {other}"))),
        }
    }

    pub fn is_index(&self) -> bool {
        matches!(self, DockerMediaType::OciIndex)
    }
}

#[derive(Debug, Clone)]
pub struct DockerBlob {
    pub digest: Digest,
    pub size_bytes: i64,
    pub storage_key: String,
    pub reference_count: i64,
}

#[derive(Debug, Clone)]
pub struct DockerManifest {
    pub id: Uuid,
    pub package_repository_id: Uuid,
    pub image_name: DockerImageName,
    pub digest: Digest,
    pub media_type: DockerMediaType,
    /// Exact bytes as received, never reparsed/reserialized — reserializing JSON can change the byte sequence a client re-verifies `digest` against.
    pub body: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DockerTag {
    pub package_repository_id: Uuid,
    pub image_name: DockerImageName,
    pub tag: String,
    pub manifest_id: Uuid,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
pub trait DockerBlobStorePort: Send + Sync {
    /// Idempotent. Does not touch `reference_count` — see `increment_ref`.
    async fn write(&self, digest: &Digest, bytes: &[u8]) -> Result<(), DomainError>;
    /// Adopts a file already on disk at `staging_path` via a rename, instead of the second full write `write` would do.
    /// `size_bytes` is recorded alongside it since the caller already knows it from streaming the file to compute `digest`.
    async fn adopt_staged_file(&self, digest: &Digest, staging_path: &str, size_bytes: u64) -> Result<(), DomainError>;
    async fn read(&self, digest: &Digest) -> Result<Vec<u8>, DomainError>;
    /// Same content as `read`, chunked instead of buffered whole — otherwise a large layer would be forced fully into memory before the first byte goes out.
    async fn read_stream(&self, digest: &Digest) -> Result<ByteStream, DomainError>;
    /// Records that `digest` was uploaded to `repository_id`, independent of any manifest referencing it yet.
    async fn link_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<(), DomainError>;
    /// One half of blob-read authorization (see `link_to_repository`); the other is `DockerManifestRepositoryPort::blob_is_reachable`.
    async fn is_uploaded_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError>;
    async fn exists(&self, digest: &Digest) -> Result<bool, DomainError>;
    async fn size_if_exists(&self, digest: &Digest) -> Result<Option<u64>, DomainError>;
    /// Batched form of `exists`: which of `digests` are present, in one query.
    async fn existing_digests(&self, digests: &[Digest]) -> Result<std::collections::HashSet<String>, DomainError>;
    /// Batched form of `size_if_exists`: total size of whichever of `digests` exist (missing ones contribute 0).
    async fn sum_sizes(&self, digests: &[Digest]) -> Result<u64, DomainError>;
    async fn increment_ref(&self, digest: &Digest) -> Result<(), DomainError>;
    /// Batched form of `increment_ref` — callers must pass already-deduplicated digests.
    async fn increment_ref_all(&self, digests: &[Digest]) -> Result<(), DomainError>;
    async fn decrement_ref_and_delete_if_zero(&self, digest: &Digest) -> Result<bool, DomainError>;
    /// Blobs are globally deduped by digest, so one blob can count toward more than one repository's total.
    async fn used_bytes_for_repository(&self, repository_id: Uuid) -> Result<u64, DomainError>;
    /// Batched `used_bytes_for_repository`. A repository with no blobs is absent, not zero.
    async fn used_bytes_for_repositories(&self, repository_ids: &[Uuid]) -> Result<std::collections::HashMap<Uuid, u64>, DomainError>;
}

#[async_trait]
pub trait DockerManifestRepositoryPort: Send + Sync {
    async fn find_manifest_by_tag(
        &self,
        repository_id: Uuid,
        image_name: &DockerImageName,
        tag: &str,
    ) -> Result<Option<DockerManifest>, DomainError>;
    async fn find_manifest_by_digest(
        &self,
        repository_id: Uuid,
        image_name: &DockerImageName,
        digest: &Digest,
    ) -> Result<Option<DockerManifest>, DomainError>;
    /// Returns the row id and whether it was a real insert (false on an idempotent conflict).
    async fn insert_manifest(&self, manifest: &DockerManifest, blob_digests: &[Digest]) -> Result<(Uuid, bool), DomainError>;
    async fn insert_manifest_list_members(&self, list_manifest_id: Uuid, member_digests: &[Digest]) -> Result<(), DomainError>;
    async fn list_manifest_blob_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError>;
    async fn list_manifest_list_member_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError>;
    async fn set_tag(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str, manifest_id: Uuid) -> Result<(), DomainError>;
    async fn delete_manifest(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest) -> Result<(), DomainError>;
    async fn list_tags(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<String>, DomainError>;
    /// Not deduplicated — callers must dedupe if needed.
    async fn list_repository_image_names(&self, repository_id: Uuid) -> Result<Vec<DockerImageName>, DomainError>;
    /// Batched form of `list_repository_image_names` across several repositories in one query.
    async fn list_image_names_for_repositories(&self, repository_ids: &[Uuid]) -> Result<Vec<(Uuid, DockerImageName)>, DomainError>;
    /// Every (image name, tag) pair in one repository, batching what would otherwise be one `list_tags` call per image.
    async fn list_all_tags_for_repository(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String)>, DomainError>;
    /// The manifest behind each image's most-recently-updated tag, one row per image name — used to resolve "the latest test" per image without an N+1 per-image lookup.
    async fn list_latest_manifest_id_per_image(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, Uuid)>, DomainError>;
    /// Distinct digests tagged anywhere on this image, in one query.
    async fn list_distinct_digests_for_image(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<Digest>, DomainError>;
    /// Every tag joined to its manifest's digest/media type/created_at, in one query.
    async fn list_tag_manifest_summaries(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<(String, Digest, DockerMediaType, DateTime<Utc>)>, DomainError>;
    /// Every image's tag/manifest summaries in one repository, batching what would otherwise be one `list_tag_manifest_summaries` call per image name.
    async fn list_repository_tag_manifest_summaries(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String, Digest, DockerMediaType, DateTime<Utc>)>, DomainError>;
    /// Whether `digest` is referenced by a manifest actually stored in `repository_id` — blob storage is globally deduped, but reads must still be scoped per repository.
    async fn blob_is_reachable(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerScopeRequest {
    pub resource_type: String,
    pub name: String,
    pub actions: Vec<String>,
}

impl DockerScopeRequest {
    /// Parses e.g. `"repository:myrepo/myimage:pull,push"`; malformed input returns `None`.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.splitn(3, ':');
        let resource_type = parts.next()?.to_string();
        let name = parts.next()?.to_string();
        let actions_part = parts.next()?;
        if resource_type.is_empty() || name.is_empty() || actions_part.is_empty() {
            return None;
        }
        Some(Self { resource_type, name, actions: actions_part.split(',').map(|s| s.to_string()).collect() })
    }

    /// The repository is the first path segment; the rest is the image name.
    pub fn hangar_repository_name(&self) -> &str {
        self.name.split('/').next().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerGrantedScope {
    pub resource_type: String,
    pub name: String,
    pub actions: Vec<String>,
    /// The repository this scope was granted against. `None` only for tokens issued before this field existed.
    pub granted_repository_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct DockerAccessClaims {
    pub user_id: Uuid,
    /// Snapshot as of token issuance, not re-checked live — used by `require_same_organization` in `hangar-docker` to reject a mismatched resolved organization.
    pub organization_id: Uuid,
    pub is_super_admin: bool,
    pub granted_scope: Option<DockerGrantedScope>,
}

#[async_trait]
pub trait DockerTokenIssuerPort: Send + Sync {
    fn issue(&self, user_id: Uuid, organization_id: Uuid, is_super_admin: bool, granted_scope: Option<DockerGrantedScope>) -> Result<String, DomainError>;
    fn verify(&self, token: &str) -> Result<DockerAccessClaims, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_valid_sha256_digest() {
        let digest = Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(digest.as_str(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn rejects_a_digest_with_the_wrong_hex_length() {
        assert!(Digest::parse("sha256:abc123").is_err());
    }

    #[test]
    fn rejects_a_digest_with_an_unsupported_algorithm() {
        assert!(Digest::parse("md5:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").is_err());
    }

    #[test]
    fn accepts_a_simple_image_name() {
        assert!(DockerImageName::parse("nginx").is_ok());
    }

    #[test]
    fn accepts_a_namespaced_image_name() {
        let name = DockerImageName::parse("library/nginx").unwrap();
        assert_eq!(name.as_str(), "library/nginx");
    }

    #[test]
    fn accepts_a_deeply_namespaced_image_name() {
        assert!(DockerImageName::parse("myorg/team/image").is_ok());
    }

    #[test]
    fn rejects_an_uppercase_image_name() {
        assert!(DockerImageName::parse("MyImage").is_err());
    }

    #[test]
    fn rejects_an_empty_image_name() {
        assert!(DockerImageName::parse("").is_err());
    }
}
