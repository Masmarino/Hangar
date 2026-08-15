use std::path::PathBuf;

use async_trait::async_trait;
use hangar_application::use_cases::docker_upload::{DockerUploadSession, DockerUploadSessionPort};
use hangar_domain::docker_registry::Digest;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub struct PostgresDockerUploadSessionRepository {
    pool: PgPool,
    staging_root: PathBuf,
}

impl PostgresDockerUploadSessionRepository {
    pub fn new(pool: PgPool, staging_root: impl Into<PathBuf>) -> Self {
        Self { pool, staging_root: staging_root.into() }
    }

    fn staging_path_for(&self, id: Uuid) -> PathBuf {
        self.staging_root.join(format!("{id}.upload"))
    }
}

#[async_trait]
impl DockerUploadSessionPort for PostgresDockerUploadSessionRepository {
    async fn create(&self, package_repository_id: Uuid) -> Result<DockerUploadSession, DomainError> {
        let id = Uuid::new_v4();
        let staging_path = self.staging_path_for(id);
        if let Some(parent) = staging_path.parent() {
            fs::create_dir_all(parent).await.infra_err()?;
        }
        fs::write(&staging_path, []).await.infra_err()?;

        let staging_path_str = staging_path.to_string_lossy().to_string();
        // No background sweep — the TTL is reclaimed lazily, in `find` below.
        let row = sqlx::query!(
            "INSERT INTO docker_blob_uploads (id, package_repository_id, staging_path, bytes_received, created_at, expires_at) \
             VALUES ($1, $2, $3, 0, now(), now() + interval '24 hours') \
             RETURNING id, package_repository_id, staging_path, bytes_received, created_at, expires_at",
            id,
            package_repository_id,
            staging_path_str,
        )
        .fetch_one(&self.pool)
        .await
        .infra_err()?;
        Ok(DockerUploadSession {
            id: row.id,
            package_repository_id: row.package_repository_id,
            staging_path: row.staging_path,
            bytes_received: row.bytes_received,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    async fn find(&self, id: Uuid) -> Result<Option<DockerUploadSession>, DomainError> {
        let row = sqlx::query!(
            "SELECT id, package_repository_id, staging_path, bytes_received, created_at, expires_at FROM docker_blob_uploads WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        let Some(row) = row else { return Ok(None) };

        if row.expires_at < chrono::Utc::now() {
            let _ = fs::remove_file(&row.staging_path).await;
            sqlx::query!("DELETE FROM docker_blob_uploads WHERE id = $1", id).execute(&self.pool).await.ok();
            return Ok(None);
        }

        Ok(Some(DockerUploadSession {
            id: row.id,
            package_repository_id: row.package_repository_id,
            staging_path: row.staging_path,
            bytes_received: row.bytes_received,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }))
    }

    async fn append_chunk(&self, id: Uuid, chunk: &[u8], expected_start: Option<i64>) -> Result<i64, DomainError> {
        // `FOR UPDATE` serializes concurrent appends to the same session, closing the check-then-act race.
        let mut tx = self.pool.begin().await.infra_err()?;
        let row = sqlx::query!("SELECT staging_path, bytes_received FROM docker_blob_uploads WHERE id = $1 FOR UPDATE", id)
            .fetch_optional(&mut *tx)
            .await
            .infra_err()?;
        let Some(row) = row else { return Err(DomainError::Infrastructure(format!("upload session not found: {id}"))) };

        if let Some(expected_start) = expected_start {
            if expected_start != row.bytes_received {
                return Err(DomainError::ChunkOffsetMismatch { expected: row.bytes_received, got: expected_start });
            }
        }

        let mut file =
            fs::OpenOptions::new().append(true).open(&row.staging_path).await.infra_err()?;
        file.write_all(chunk).await.infra_err()?;

        let updated = sqlx::query!(
            "UPDATE docker_blob_uploads SET bytes_received = bytes_received + $2 WHERE id = $1 RETURNING bytes_received",
            id,
            chunk.len() as i64
        )
        .fetch_one(&mut *tx)
        .await
        .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok(updated.bytes_received)
    }

    async fn hash_staged_file(&self, id: Uuid) -> Result<(Digest, u64), DomainError> {
        let session = self.find(id).await?.ok_or_else(|| DomainError::Infrastructure(format!("upload session not found: {id}")))?;
        let mut file = fs::File::open(&session.staging_path).await.infra_err()?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = file.read(&mut buf).await.infra_err()?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).expect("well-formed sha256 hex digest");
        Ok((digest, total))
    }

    async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
        if let Some(session) = self.find(id).await? {
            let _ = fs::remove_file(&session.staging_path).await;
        }
        sqlx::query!("DELETE FROM docker_blob_uploads WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_repository(pool: &sqlx::PgPool, id: Uuid) {
        sqlx::query!(
            "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, version, created_at, updated_at) \
             VALUES ($1, $2, $3, 'docker', 'hosted', NULL, 1, now(), now())",
            id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            format!("repo-{id}"),
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn creates_a_session_with_zero_bytes_received(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = PostgresDockerUploadSessionRepository::new(pool, dir.path());

        let session = sessions.create(repository_id).await.unwrap();

        assert_eq!(session.package_repository_id, repository_id);
        assert_eq!(session.bytes_received, 0);
        assert_eq!(sessions.find(session.id).await.unwrap().unwrap().id, session.id);
    }

    #[sqlx::test]
    async fn appending_chunks_accumulates_bytes_in_order(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = PostgresDockerUploadSessionRepository::new(pool, dir.path());
        let session = sessions.create(repository_id).await.unwrap();

        let total_after_first = sessions.append_chunk(session.id, b"hello-", Some(0)).await.unwrap();
        let total_after_second = sessions.append_chunk(session.id, b"world", Some(6)).await.unwrap();

        assert_eq!(total_after_first, 6);
        assert_eq!(total_after_second, 11);
        assert_eq!(sessions.hash_staged_file(session.id).await.unwrap(), (Digest::of(b"hello-world"), 11));
        assert_eq!(sessions.find(session.id).await.unwrap().unwrap().bytes_received, 11);
    }

    /// Larger than the 64 KiB read buffer `hash_staged_file` uses internally, so this actually
    /// exercises more than one read/hash-update iteration.
    #[sqlx::test]
    async fn hash_staged_file_matches_a_one_shot_hash_for_content_spanning_multiple_reads(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = PostgresDockerUploadSessionRepository::new(pool, dir.path());
        let session = sessions.create(repository_id).await.unwrap();
        let content = vec![0xABu8; 200 * 1024];
        sessions.append_chunk(session.id, &content, Some(0)).await.unwrap();

        let (digest, size) = sessions.hash_staged_file(session.id).await.unwrap();

        assert_eq!(digest, Digest::of(&content));
        assert_eq!(size, content.len() as u64);
    }

    #[sqlx::test]
    async fn concurrent_appends_do_not_lose_a_chunks_contribution_to_the_byte_count(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = std::sync::Arc::new(PostgresDockerUploadSessionRepository::new(pool, dir.path()));
        let session = sessions.create(repository_id).await.unwrap();

        let a = sessions.clone();
        let b = sessions.clone();
        let id = session.id;
        let (result_a, result_b) = tokio::join!(a.append_chunk(id, &[0u8; 100], None), b.append_chunk(id, &[0u8; 50], None));
        result_a.unwrap();
        result_b.unwrap();

        assert_eq!(sessions.find(id).await.unwrap().unwrap().bytes_received, 150, "both concurrent chunks must be counted, not just the last writer");
    }

    #[sqlx::test]
    async fn two_concurrent_chunks_claiming_the_same_offset_only_let_one_through(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = std::sync::Arc::new(PostgresDockerUploadSessionRepository::new(pool, dir.path()));
        let session = sessions.create(repository_id).await.unwrap();

        let a = sessions.clone();
        let b = sessions.clone();
        let id = session.id;
        let (result_a, result_b) = tokio::join!(a.append_chunk(id, &[1u8; 10], Some(0)), b.append_chunk(id, &[2u8; 10], Some(0)));

        let outcomes = [result_a, result_b];
        let successes = outcomes.iter().filter(|r| r.is_ok()).count();
        let mismatches = outcomes.iter().filter(|r| matches!(r, Err(DomainError::ChunkOffsetMismatch { .. }))).count();
        assert_eq!(successes, 1, "only one of two chunks claiming the same start offset may be accepted");
        assert_eq!(mismatches, 1, "the loser must see a clear offset mismatch, not silently corrupt the stream");
        assert_eq!(sessions.find(id).await.unwrap().unwrap().bytes_received, 10, "only the winning chunk's bytes were counted");
    }

    #[sqlx::test]
    async fn deleting_a_session_removes_its_row_and_staging_file(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = PostgresDockerUploadSessionRepository::new(pool, dir.path());
        let session = sessions.create(repository_id).await.unwrap();
        sessions.append_chunk(session.id, b"data", None).await.unwrap();

        sessions.delete(session.id).await.unwrap();

        assert!(sessions.find(session.id).await.unwrap().is_none());
        assert!(sessions.hash_staged_file(session.id).await.is_err());
    }

    #[sqlx::test]
    async fn an_expired_session_is_lazily_swept_on_the_next_find(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let sessions = PostgresDockerUploadSessionRepository::new(pool.clone(), dir.path());
        let session = sessions.create(repository_id).await.unwrap();
        sqlx::query!("UPDATE docker_blob_uploads SET expires_at = now() - interval '1 hour' WHERE id = $1", session.id)
            .execute(&pool)
            .await
            .unwrap();

        assert!(sessions.find(session.id).await.unwrap().is_none());
        let remaining: i64 = sqlx::query_scalar!("SELECT count(*) FROM docker_blob_uploads WHERE id = $1", session.id).fetch_one(&pool).await.unwrap().unwrap();
        assert_eq!(remaining, 0);
        assert!(!std::path::Path::new(&session.staging_path).exists());
    }
}
