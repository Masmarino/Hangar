use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use hangar_domain::audit::{AuditEntry, AuditQueryFilter, DockerRegistryEvent, EventPublisherPort, NpmPackageEvent, SecurityEvent};
use hangar_domain::docker_registry::{
    Digest, DockerAccessClaims, DockerBlobStorePort, DockerGrantedScope, DockerImageName, DockerManifest, DockerManifestRepositoryPort, DockerMediaType, DockerTokenIssuerPort,
};
use hangar_domain::docker_remote::RemoteDockerRegistryPort;
use hangar_domain::docker_scan::{DockerImageScanRepositoryPort, DockerImageScanResult, DockerImageScannerPort, DockerVulnerability};
use hangar_domain::error::{DomainError, EventStoreError};
use hangar_domain::package_repository::{PackageRepositoryQueryPort, PackageRepositorySummary};
use uuid::Uuid;

use crate::use_cases::docker_upload::{DockerUploadSession, DockerUploadSessionPort};

pub struct FakeUploadSessions {
    pub sessions: Mutex<HashMap<Uuid, (DockerUploadSession, Vec<u8>)>>,
}

impl FakeUploadSessions {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }
}

#[async_trait]
impl DockerUploadSessionPort for FakeUploadSessions {
    async fn create(&self, package_repository_id: Uuid) -> Result<DockerUploadSession, DomainError> {
        let session = DockerUploadSession {
            id: Uuid::new_v4(),
            package_repository_id,
            staging_path: String::new(),
            bytes_received: 0,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        };
        self.sessions.lock().unwrap().insert(session.id, (session.clone(), Vec::new()));
        Ok(session)
    }
    async fn find(&self, id: Uuid) -> Result<Option<DockerUploadSession>, DomainError> {
        Ok(self.sessions.lock().unwrap().get(&id).map(|(s, _)| s.clone()))
    }
    async fn append_chunk(&self, id: Uuid, chunk: &[u8], expected_start: Option<i64>) -> Result<i64, DomainError> {
        let mut sessions = self.sessions.lock().unwrap();
        let (session, bytes) = sessions.get_mut(&id).ok_or_else(|| DomainError::Infrastructure("session not found".into()))?;
        if let Some(expected_start) = expected_start {
            if expected_start != session.bytes_received {
                return Err(DomainError::ChunkOffsetMismatch { expected: session.bytes_received, got: expected_start });
            }
        }
        bytes.extend_from_slice(chunk);
        session.bytes_received = bytes.len() as i64;
        Ok(session.bytes_received)
    }
    async fn hash_staged_file(&self, id: Uuid) -> Result<(Digest, u64), DomainError> {
        let bytes = self.sessions.lock().unwrap().get(&id).map(|(_, bytes)| bytes.clone()).ok_or_else(|| DomainError::Infrastructure("session not found".into()))?;
        Ok((Digest::of(&bytes), bytes.len() as u64))
    }
    async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
        self.sessions.lock().unwrap().remove(&id);
        Ok(())
    }
}

pub struct FakeDockerBlobStore {
    pub blobs: Mutex<HashMap<String, (Vec<u8>, i64)>>, // digest string -> (bytes, ref_count)
    pub repository_links: Mutex<HashSet<(Uuid, String)>>,
}

impl FakeDockerBlobStore {
    pub fn new() -> Self {
        Self { blobs: Mutex::new(HashMap::new()), repository_links: Mutex::new(HashSet::new()) }
    }
}

#[async_trait]
impl DockerBlobStorePort for FakeDockerBlobStore {
    async fn write(&self, digest: &Digest, bytes: &[u8]) -> Result<(), DomainError> {
        let mut blobs = self.blobs.lock().unwrap();
        blobs.entry(digest.as_str().to_string()).or_insert_with(|| (bytes.to_vec(), 0));
        Ok(())
    }
    async fn adopt_staged_file(&self, digest: &Digest, _staging_path: &str, size_bytes: u64) -> Result<(), DomainError> {
        // Unlike `write`, this never receives the real content — a placeholder of the right length is enough for what this fake's callers actually check (existence and size).
        let mut blobs = self.blobs.lock().unwrap();
        blobs.entry(digest.as_str().to_string()).or_insert_with(|| (vec![0u8; size_bytes as usize], 0));
        Ok(())
    }
    async fn read(&self, digest: &Digest) -> Result<Vec<u8>, DomainError> {
        self.blobs.lock().unwrap().get(digest.as_str()).map(|(bytes, _)| bytes.clone()).ok_or_else(|| DomainError::Infrastructure("not found".into()))
    }
    async fn read_stream(&self, digest: &Digest) -> Result<hangar_domain::docker_registry::ByteStream, DomainError> {
        let bytes = self.read(digest).await?;
        Ok(Box::pin(futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) })))
    }
    async fn link_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<(), DomainError> {
        self.repository_links.lock().unwrap().insert((repository_id, digest.as_str().to_string()));
        Ok(())
    }
    async fn is_uploaded_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError> {
        Ok(self.repository_links.lock().unwrap().contains(&(repository_id, digest.as_str().to_string())))
    }
    async fn exists(&self, digest: &Digest) -> Result<bool, DomainError> {
        Ok(self.blobs.lock().unwrap().contains_key(digest.as_str()))
    }
    async fn size_if_exists(&self, digest: &Digest) -> Result<Option<u64>, DomainError> {
        Ok(self.blobs.lock().unwrap().get(digest.as_str()).map(|(bytes, _)| bytes.len() as u64))
    }
    async fn existing_digests(&self, digests: &[Digest]) -> Result<HashSet<String>, DomainError> {
        let blobs = self.blobs.lock().unwrap();
        Ok(digests.iter().map(|d| d.as_str().to_string()).filter(|d| blobs.contains_key(d)).collect())
    }
    async fn sum_sizes(&self, digests: &[Digest]) -> Result<u64, DomainError> {
        let blobs = self.blobs.lock().unwrap();
        Ok(digests.iter().filter_map(|d| blobs.get(d.as_str())).map(|(bytes, _)| bytes.len() as u64).sum())
    }
    async fn increment_ref(&self, digest: &Digest) -> Result<(), DomainError> {
        if let Some((_, count)) = self.blobs.lock().unwrap().get_mut(digest.as_str()) {
            *count += 1;
        }
        Ok(())
    }
    async fn increment_ref_all(&self, digests: &[Digest]) -> Result<(), DomainError> {
        let mut blobs = self.blobs.lock().unwrap();
        for digest in digests {
            if let Some((_, count)) = blobs.get_mut(digest.as_str()) {
                *count += 1;
            }
        }
        Ok(())
    }
    async fn decrement_ref_and_delete_if_zero(&self, digest: &Digest) -> Result<bool, DomainError> {
        let mut blobs = self.blobs.lock().unwrap();
        if let Some((_, count)) = blobs.get_mut(digest.as_str()) {
            *count -= 1;
            if *count <= 0 {
                blobs.remove(digest.as_str());
                return Ok(true);
            }
        }
        Ok(false)
    }
    async fn used_bytes_for_repository(&self, _repository_id: Uuid) -> Result<u64, DomainError> {
        // Digest-keyed only, no per-repository tracking — always reports zero pre-existing usage.
        Ok(0)
    }
    async fn used_bytes_for_repositories(&self, _repository_ids: &[Uuid]) -> Result<HashMap<Uuid, u64>, DomainError> {
        Ok(HashMap::new())
    }
}

pub struct FakeDockerManifestRepository {
    pub manifests: Mutex<HashMap<Uuid, DockerManifest>>,
    pub manifest_blobs: Mutex<HashMap<Uuid, Vec<Digest>>>,
    pub manifest_list_members: Mutex<HashMap<Uuid, Vec<Digest>>>,
    pub tags: Mutex<HashMap<(Uuid, String, String), Uuid>>, // (repo_id, image_name, tag) -> manifest_id
}

impl FakeDockerManifestRepository {
    pub fn new() -> Self {
        Self {
            manifests: Mutex::new(HashMap::new()),
            manifest_blobs: Mutex::new(HashMap::new()),
            manifest_list_members: Mutex::new(HashMap::new()),
            tags: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl DockerManifestRepositoryPort for FakeDockerManifestRepository {
    async fn find_manifest_by_tag(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str) -> Result<Option<DockerManifest>, DomainError> {
        let tags = self.tags.lock().unwrap();
        let Some(manifest_id) = tags.get(&(repository_id, image_name.as_str().to_string(), tag.to_string())) else { return Ok(None) };
        Ok(self.manifests.lock().unwrap().get(manifest_id).cloned())
    }
    async fn find_manifest_by_digest(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest) -> Result<Option<DockerManifest>, DomainError> {
        Ok(self.manifests.lock().unwrap().values().find(|m| m.package_repository_id == repository_id && &m.image_name == image_name && &m.digest == digest).cloned())
    }
    async fn insert_manifest(&self, manifest: &DockerManifest, blob_digests: &[Digest]) -> Result<(Uuid, bool), DomainError> {
        // Mirrors the real ON CONFLICT DO NOTHING: an existing (repository, image, digest) keeps its id.
        let existing_id = self
            .manifests
            .lock()
            .unwrap()
            .values()
            .find(|m| m.package_repository_id == manifest.package_repository_id && m.image_name == manifest.image_name && m.digest == manifest.digest)
            .map(|m| m.id);
        if let Some(existing_id) = existing_id {
            return Ok((existing_id, false));
        }
        self.manifests.lock().unwrap().insert(manifest.id, manifest.clone());
        self.manifest_blobs.lock().unwrap().insert(manifest.id, blob_digests.to_vec());
        Ok((manifest.id, true))
    }
    async fn insert_manifest_list_members(&self, list_manifest_id: Uuid, member_digests: &[Digest]) -> Result<(), DomainError> {
        self.manifest_list_members.lock().unwrap().insert(list_manifest_id, member_digests.to_vec());
        Ok(())
    }
    async fn list_manifest_blob_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError> {
        Ok(self.manifest_blobs.lock().unwrap().get(&manifest_id).cloned().unwrap_or_default())
    }
    async fn list_manifest_list_member_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError> {
        Ok(self.manifest_list_members.lock().unwrap().get(&manifest_id).cloned().unwrap_or_default())
    }
    async fn set_tag(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str, manifest_id: Uuid) -> Result<(), DomainError> {
        self.tags.lock().unwrap().insert((repository_id, image_name.as_str().to_string(), tag.to_string()), manifest_id);
        Ok(())
    }
    async fn delete_manifest(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest) -> Result<(), DomainError> {
        let manifest_id = self.manifests.lock().unwrap().values().find(|m| m.package_repository_id == repository_id && &m.image_name == image_name && &m.digest == digest).map(|m| m.id);
        if let Some(id) = manifest_id {
            self.manifests.lock().unwrap().remove(&id);
            self.manifest_blobs.lock().unwrap().remove(&id);
            self.tags.lock().unwrap().retain(|_, v| *v != id);
        }
        Ok(())
    }
    async fn list_tags(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<String>, DomainError> {
        Ok(self.tags.lock().unwrap().keys().filter(|(rid, name, _)| *rid == repository_id && name == image_name.as_str()).map(|(_, _, tag)| tag.clone()).collect())
    }
    async fn list_repository_image_names(&self, repository_id: Uuid) -> Result<Vec<DockerImageName>, DomainError> {
        // Intentionally not deduplicating — ListCatalogUseCase is the sole place responsible for that.
        let names: Vec<String> = self.tags.lock().unwrap().keys().filter(|(rid, _, _)| *rid == repository_id).map(|(_, name, _)| name.clone()).collect();
        names.into_iter().map(|n| DockerImageName::parse(&n)).collect()
    }
    async fn list_image_names_for_repositories(&self, repository_ids: &[Uuid]) -> Result<Vec<(Uuid, DockerImageName)>, DomainError> {
        let mut pairs: Vec<(Uuid, String)> =
            self.tags.lock().unwrap().keys().filter(|(rid, _, _)| repository_ids.contains(rid)).map(|(rid, name, _)| (*rid, name.clone())).collect();
        pairs.sort();
        pairs.dedup();
        Ok(pairs.into_iter().filter_map(|(rid, name)| DockerImageName::parse(&name).ok().map(|n| (rid, n))).collect())
    }
    async fn list_all_tags_for_repository(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String)>, DomainError> {
        let mut pairs: Vec<(String, String)> =
            self.tags.lock().unwrap().keys().filter(|(rid, _, _)| *rid == repository_id).map(|(_, name, tag)| (name.clone(), tag.clone())).collect();
        pairs.sort();
        pairs.into_iter().map(|(name, tag)| DockerImageName::parse(&name).map(|n| (n, tag))).collect()
    }
    async fn list_distinct_digests_for_image(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<Digest>, DomainError> {
        let manifest_ids: Vec<Uuid> =
            self.tags.lock().unwrap().iter().filter(|((rid, name, _), _)| *rid == repository_id && name == image_name.as_str()).map(|(_, id)| *id).collect();
        let manifests = self.manifests.lock().unwrap();
        let mut digests: Vec<Digest> = manifest_ids.into_iter().filter_map(|id| manifests.get(&id).map(|m| m.digest.clone())).collect();
        digests.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        digests.dedup();
        Ok(digests)
    }
    async fn list_tag_manifest_summaries(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<(String, Digest, DockerMediaType, chrono::DateTime<chrono::Utc>)>, DomainError> {
        let tags = self.tags.lock().unwrap();
        let manifests = self.manifests.lock().unwrap();
        let mut summaries: Vec<(String, Digest, DockerMediaType, chrono::DateTime<chrono::Utc>)> = tags
            .iter()
            .filter(|((rid, name, _), _)| *rid == repository_id && name == image_name.as_str())
            .filter_map(|((_, _, tag), manifest_id)| manifests.get(manifest_id).map(|m| (tag.clone(), m.digest.clone(), m.media_type.clone(), m.created_at)))
            .collect();
        summaries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(summaries)
    }
    async fn list_repository_tag_manifest_summaries(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String, Digest, DockerMediaType, chrono::DateTime<chrono::Utc>)>, DomainError> {
        let tags = self.tags.lock().unwrap();
        let manifests = self.manifests.lock().unwrap();
        let mut summaries: Vec<(DockerImageName, String, Digest, DockerMediaType, chrono::DateTime<chrono::Utc>)> = tags
            .iter()
            .filter(|((rid, _, _), _)| *rid == repository_id)
            .filter_map(|((_, name, tag), manifest_id)| {
                let manifest = manifests.get(manifest_id)?;
                Some((DockerImageName::parse(name).ok()?, tag.clone(), manifest.digest.clone(), manifest.media_type.clone(), manifest.created_at))
            })
            .collect();
        summaries.sort_by(|a, b| (a.0.as_str(), &a.1).cmp(&(b.0.as_str(), &b.1)));
        Ok(summaries)
    }

    async fn blob_is_reachable(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError> {
        let manifests = self.manifests.lock().unwrap();
        let manifest_blobs = self.manifest_blobs.lock().unwrap();
        Ok(manifests.values().any(|m| m.package_repository_id == repository_id && manifest_blobs.get(&m.id).is_some_and(|blobs| blobs.contains(digest))))
    }
}

pub struct FakeDockerEvents {
    pub docker_events: Mutex<Vec<(DockerRegistryEvent, Uuid, Option<Uuid>)>>,
}

impl FakeDockerEvents {
    pub fn new() -> Self {
        Self { docker_events: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl EventPublisherPort for FakeDockerEvents {
    async fn publish_security_event(&self, _event: SecurityEvent, _actor_id: Option<Uuid>) -> Result<(), EventStoreError> { Ok(()) }
    async fn query_audit_log(&self, _filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, EventStoreError> { Ok(vec![]) }
    async fn publish_npm_event(&self, _event: NpmPackageEvent, _npm_package_id: Uuid, _actor_id: Option<Uuid>) -> Result<(), EventStoreError> { Ok(()) }
    async fn publish_docker_event(&self, event: DockerRegistryEvent, package_repository_id: Uuid, actor_id: Option<Uuid>) -> Result<(), EventStoreError> {
        self.docker_events.lock().unwrap().push((event, package_repository_id, actor_id));
        Ok(())
    }
}

pub struct FakeRepositories {
    pub repos: Mutex<HashMap<Uuid, PackageRepositorySummary>>,
}

impl FakeRepositories {
    pub fn new() -> Self {
        Self { repos: Mutex::new(HashMap::new()) }
    }

    pub fn insert(&self, repo: PackageRepositorySummary) {
        self.repos.lock().unwrap().insert(repo.id, repo);
    }
}

#[async_trait]
impl PackageRepositoryQueryPort for FakeRepositories {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repos.lock().unwrap().get(&id).cloned())
    }
    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repos.lock().unwrap().values().find(|r| r.organization_id == organization_id && r.name == name).cloned())
    }
    async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError> {
        Ok(self.repos.lock().unwrap().values().cloned().collect())
    }
}

pub struct FakeDockerTokenIssuer {
    pub issued: Mutex<Vec<(Uuid, Option<DockerGrantedScope>)>>,
}

impl FakeDockerTokenIssuer {
    pub fn new() -> Self {
        Self { issued: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl DockerTokenIssuerPort for FakeDockerTokenIssuer {
    fn issue(&self, user_id: Uuid, _organization_id: Uuid, _is_super_admin: bool, granted_scope: Option<DockerGrantedScope>) -> Result<String, DomainError> {
        self.issued.lock().unwrap().push((user_id, granted_scope));
        Ok("fake-registry-token".to_string())
    }
    fn verify(&self, _token: &str) -> Result<DockerAccessClaims, DomainError> {
        unreachable!("not exercised by ScanDockerImageUseCase's tests")
    }
}

/// Returns a fixed list of vulnerabilities and records the arguments it was scanned with.
pub struct FakeDockerImageScanner {
    pub vulnerabilities: Vec<DockerVulnerability>,
    pub last_call: Mutex<Option<(String, String, String, Option<String>, String)>>,
}

impl FakeDockerImageScanner {
    pub fn new(vulnerabilities: Vec<DockerVulnerability>) -> Self {
        Self { vulnerabilities, last_call: Mutex::new(None) }
    }
}

#[async_trait]
impl DockerImageScannerPort for FakeDockerImageScanner {
    async fn scan(
        &self,
        repository_name: &str,
        image_name: &str,
        reference: &str,
        platform: Option<&str>,
        registry_token: &str,
    ) -> Result<Vec<DockerVulnerability>, DomainError> {
        *self.last_call.lock().unwrap() =
            Some((repository_name.to_string(), image_name.to_string(), reference.to_string(), platform.map(str::to_string), registry_token.to_string()));
        Ok(self.vulnerabilities.clone())
    }
}

/// Mirrors the Postgres adapter's "insert-only, latest wins by `scanned_at`" semantics.
pub struct FakeDockerImageScanResults {
    pub saved: Mutex<Vec<DockerImageScanResult>>,
}

impl FakeDockerImageScanResults {
    pub fn new() -> Self {
        Self { saved: Mutex::new(Vec::new()) }
    }
}

#[async_trait]
impl DockerImageScanRepositoryPort for FakeDockerImageScanResults {
    async fn save(&self, result: &DockerImageScanResult) -> Result<(), DomainError> {
        self.saved.lock().unwrap().push(result.clone());
        Ok(())
    }
    async fn find_latest_for_manifest(&self, docker_manifest_id: Uuid) -> Result<Option<DockerImageScanResult>, DomainError> {
        Ok(self.saved.lock().unwrap().iter().filter(|r| r.docker_manifest_id == docker_manifest_id).max_by_key(|r| r.scanned_at).cloned())
    }
}

/// `manifest_response == None` simulates a real 404 (`Ok(None)`), not a fetch error.
pub struct FakeRemoteDockerRegistry {
    pub manifest_response: Mutex<Option<(Vec<u8>, String)>>,
}

impl FakeRemoteDockerRegistry {
    pub fn new() -> Self {
        Self { manifest_response: Mutex::new(Some((b"{}".to_vec(), "application/vnd.docker.distribution.manifest.v2+json".to_string()))) }
    }
}

#[async_trait]
impl RemoteDockerRegistryPort for FakeRemoteDockerRegistry {
    async fn fetch_manifest(
        &self,
        _base_url: &str,
        _image_name: &DockerImageName,
        _reference: &str,
        _username: Option<&str>,
        _password: Option<&str>,
    ) -> Result<Option<(Vec<u8>, String)>, DomainError> {
        Ok(self.manifest_response.lock().unwrap().clone())
    }
    async fn fetch_blob(
        &self,
        _base_url: &str,
        _image_name: &DockerImageName,
        _digest: &Digest,
        _username: Option<&str>,
        _password: Option<&str>,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(Some(b"fake-blob-bytes".to_vec()))
    }
}
