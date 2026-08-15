use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::{Digest, DockerBlobStorePort};
use hangar_domain::error::DomainError;
use uuid::Uuid;

use crate::error::ApplicationError;

/// Fetches the session and checks it belongs to `repository_id`, treating a foreign session the same as a nonexistent one.
async fn find_own_session(sessions: &dyn DockerUploadSessionPort, session_id: Uuid, repository_id: Uuid) -> Result<DockerUploadSession, ApplicationError> {
    let Some(session) = sessions.find(session_id).await? else {
        return Err(ApplicationError::DockerUploadSessionNotFound);
    };
    if session.package_repository_id != repository_id {
        return Err(ApplicationError::DockerUploadSessionNotFound);
    }
    Ok(session)
}

#[derive(Debug, Clone)]
pub struct DockerUploadSession {
    pub id: Uuid,
    pub package_repository_id: Uuid,
    pub staging_path: String,
    pub bytes_received: i64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait DockerUploadSessionPort: Send + Sync {
    /// No background sweep: an abandoned session is cleaned up lazily, on the next `find`.
    async fn create(&self, package_repository_id: Uuid) -> Result<DockerUploadSession, DomainError>;
    /// Returns `None` for an expired session even if its row still exists — callers can't distinguish "never existed" from "expired".
    async fn find(&self, id: Uuid) -> Result<Option<DockerUploadSession>, DomainError>;
    /// Checks `expected_start` and applies the chunk as one atomic step, if given.
    async fn append_chunk(&self, id: Uuid, chunk: &[u8], expected_start: Option<i64>) -> Result<i64, DomainError>;
    /// Streams the staged content from disk to hash it — a chunked upload can be gigabytes.
    async fn hash_staged_file(&self, id: Uuid) -> Result<(Digest, u64), DomainError>;
    async fn delete(&self, id: Uuid) -> Result<(), DomainError>;
}

pub struct StartBlobUploadUseCase {
    sessions: Arc<dyn DockerUploadSessionPort>,
}

impl StartBlobUploadUseCase {
    pub fn new(sessions: Arc<dyn DockerUploadSessionPort>) -> Self {
        Self { sessions }
    }

    pub async fn execute(&self, repository_id: Uuid) -> Result<DockerUploadSession, ApplicationError> {
        Ok(self.sessions.create(repository_id).await?)
    }
}

pub struct PatchBlobUploadUseCase {
    sessions: Arc<dyn DockerUploadSessionPort>,
}

impl PatchBlobUploadUseCase {
    pub fn new(sessions: Arc<dyn DockerUploadSessionPort>) -> Self {
        Self { sessions }
    }

    /// `expected_start`, from a client-sent `Content-Range`, must match the offset at write time.
    pub async fn execute(&self, session_id: Uuid, repository_id: Uuid, chunk: &[u8], expected_start: Option<i64>) -> Result<i64, ApplicationError> {
        find_own_session(&*self.sessions, session_id, repository_id).await?;
        match self.sessions.append_chunk(session_id, chunk, expected_start).await {
            Err(DomainError::ChunkOffsetMismatch { expected, got }) => Err(ApplicationError::DockerChunkOffsetMismatch { expected, got }),
            other => Ok(other?),
        }
    }
}

pub struct CompleteBlobUploadUseCase {
    sessions: Arc<dyn DockerUploadSessionPort>,
    blobs: Arc<dyn DockerBlobStorePort>,
}

impl CompleteBlobUploadUseCase {
    pub fn new(sessions: Arc<dyn DockerUploadSessionPort>, blobs: Arc<dyn DockerBlobStorePort>) -> Self {
        Self { sessions, blobs }
    }

    /// Verifies staged bytes hash to `expected_digest` before storing — never trusts the client's claim. Doesn't increment the blob's ref count; that's `PutManifestUseCase`'s job.
    pub async fn execute(&self, session_id: Uuid, repository_id: Uuid, expected_digest: &Digest) -> Result<(), ApplicationError> {
        let session = find_own_session(&*self.sessions, session_id, repository_id).await?;
        let (computed, size_bytes) = self.sessions.hash_staged_file(session_id).await?;
        if &computed != expected_digest {
            return Err(ApplicationError::DockerDigestMismatch {
                expected: expected_digest.as_str().to_string(),
                computed: computed.as_str().to_string(),
            });
        }
        // The staged file already holds these exact bytes — adopt it in place, no second full copy.
        self.blobs.adopt_staged_file(&computed, &session.staging_path, size_bytes).await?;
        self.blobs.link_to_repository(session.package_repository_id, &computed).await?;
        self.sessions.delete(session_id).await?;
        Ok(())
    }
}

pub struct MonolithicBlobUploadUseCase {
    blobs: Arc<dyn DockerBlobStorePort>,
}

impl MonolithicBlobUploadUseCase {
    pub fn new(blobs: Arc<dyn DockerBlobStorePort>) -> Self {
        Self { blobs }
    }

    /// Single-POST-with-body upload for small-to-medium layers — no session tracking needed.
    pub async fn execute(&self, repository_id: Uuid, expected_digest: &Digest, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let (computed, bytes) = hash_blob(bytes).await?;
        if &computed != expected_digest {
            return Err(ApplicationError::DockerDigestMismatch {
                expected: expected_digest.as_str().to_string(),
                computed: computed.as_str().to_string(),
            });
        }
        self.blobs.write(&computed, &bytes).await?;
        self.blobs.link_to_repository(repository_id, &computed).await?;
        Ok(())
    }
}

/// Hashing is CPU-bound, off the async executor so a large layer doesn't stall other requests. Returns the bytes back so callers don't need a second copy.
async fn hash_blob(bytes: Vec<u8>) -> Result<(Digest, Vec<u8>), ApplicationError> {
    tokio::task::spawn_blocking(move || {
        let digest = Digest::of(&bytes);
        (digest, bytes)
    })
    .await
    .map_err(|e| hangar_domain::error::DomainError::Infrastructure(e.to_string()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::docker_test_support::{FakeDockerBlobStore, FakeUploadSessions};
    use hangar_domain::docker_registry::Digest;

    #[tokio::test]
    async fn starting_an_upload_creates_a_session() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let use_case = StartBlobUploadUseCase::new(sessions);
        let repository_id = Uuid::new_v4();
        let session = use_case.execute(repository_id).await.unwrap();
        assert_eq!(session.bytes_received, 0);
    }

    #[tokio::test]
    async fn patching_appends_bytes_and_reports_the_new_total() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let repository_id = Uuid::new_v4();
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(repository_id).await.unwrap();

        let use_case = PatchBlobUploadUseCase::new(sessions);
        let total = use_case.execute(session.id, repository_id, b"hello ", None).await.unwrap();
        assert_eq!(total, 6);
        let total = use_case.execute(session.id, repository_id, b"world", Some(6)).await.unwrap();
        assert_eq!(total, 11);
    }

    #[tokio::test]
    async fn patching_with_a_content_range_start_that_does_not_match_the_current_offset_is_rejected() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let repository_id = Uuid::new_v4();
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(repository_id).await.unwrap();
        let use_case = PatchBlobUploadUseCase::new(sessions);
        use_case.execute(session.id, repository_id, b"hello ", None).await.unwrap();

        // A retried or reordered chunk claiming to start at 0 when 6 bytes are already staged.
        let err = use_case.execute(session.id, repository_id, b"world", Some(0)).await.unwrap_err();

        assert!(matches!(err, ApplicationError::DockerChunkOffsetMismatch { expected: 6, got: 0 }), "got {err:?}");
    }

    #[tokio::test]
    async fn patching_a_session_through_a_different_repositorys_authorization_is_rejected() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(Uuid::new_v4()).await.unwrap();
        let use_case = PatchBlobUploadUseCase::new(sessions);

        let err = use_case.execute(session.id, Uuid::new_v4(), b"hello", None).await.unwrap_err();

        assert!(matches!(err, ApplicationError::DockerUploadSessionNotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn completing_verifies_the_digest_and_stores_the_blob() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let repository_id = Uuid::new_v4();
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(repository_id).await.unwrap();
        let patch = PatchBlobUploadUseCase::new(sessions.clone());
        patch.execute(session.id, repository_id, b"blob-bytes", None).await.unwrap();

        let real_digest = Digest::of(b"blob-bytes");
        let use_case = CompleteBlobUploadUseCase::new(sessions, blobs.clone());
        use_case.execute(session.id, repository_id, &real_digest).await.unwrap();

        assert!(blobs.exists(&real_digest).await.unwrap());
    }

    #[tokio::test]
    async fn completing_with_a_mismatched_digest_is_rejected() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let repository_id = Uuid::new_v4();
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(repository_id).await.unwrap();
        let patch = PatchBlobUploadUseCase::new(sessions.clone());
        patch.execute(session.id, repository_id, b"blob-bytes", None).await.unwrap();

        let wrong_digest = Digest::of(b"different-bytes");
        let use_case = CompleteBlobUploadUseCase::new(sessions, blobs.clone());
        let result = use_case.execute(session.id, repository_id, &wrong_digest).await;
        assert!(matches!(result, Err(ApplicationError::DockerDigestMismatch { .. })));
        assert!(!blobs.exists(&wrong_digest).await.unwrap());
    }

    #[tokio::test]
    async fn completing_a_session_through_a_different_repositorys_authorization_is_rejected() {
        let sessions = Arc::new(FakeUploadSessions::new());
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let victim_repository_id = Uuid::new_v4();
        let start = StartBlobUploadUseCase::new(sessions.clone());
        let session = start.execute(victim_repository_id).await.unwrap();
        let patch = PatchBlobUploadUseCase::new(sessions.clone());
        patch.execute(session.id, victim_repository_id, b"blob-bytes", None).await.unwrap();

        let digest = Digest::of(b"blob-bytes");
        let use_case = CompleteBlobUploadUseCase::new(sessions, blobs.clone());
        let attacker_repository_id = Uuid::new_v4();
        let err = use_case.execute(session.id, attacker_repository_id, &digest).await.unwrap_err();

        assert!(matches!(err, ApplicationError::DockerUploadSessionNotFound), "got {err:?}");
        assert!(!blobs.exists(&digest).await.unwrap(), "the blob must not be linked anywhere when the repository check fails");
    }

    #[tokio::test]
    async fn monolithic_upload_verifies_and_stores_in_one_call() {
        let blobs = Arc::new(FakeDockerBlobStore::new());
        let use_case = MonolithicBlobUploadUseCase::new(blobs.clone());
        let digest = Digest::of(b"monolithic-bytes");
        use_case.execute(Uuid::new_v4(), &digest, b"monolithic-bytes".to_vec()).await.unwrap();
        assert!(blobs.exists(&digest).await.unwrap());
    }
}
