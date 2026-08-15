use std::path::PathBuf;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use hangar_domain::docker_registry::{ByteStream, Digest, DockerBlobStorePort};
use hangar_domain::error::DomainError;
use sqlx::PgPool;
use tokio::fs;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::error_ext::InfraErr;

pub struct FilesystemDockerBlobStore {
    pool: PgPool,
    root: PathBuf,
}

impl FilesystemDockerBlobStore {
    pub fn new(pool: PgPool, root: impl Into<PathBuf>) -> Self {
        Self { pool, root: root.into() }
    }

    fn hex_part(digest: &Digest) -> Result<&str, DomainError> {
        digest.as_str().strip_prefix("sha256:").ok_or_else(|| DomainError::Validation(format!("unsupported digest algorithm: {}", digest.as_str())))
    }

    /// Shards two levels deep by the digest's first four hex chars.
    fn storage_key(hex: &str) -> String {
        format!("sha256/{}/{}/{}", &hex[0..2], &hex[2..4], hex)
    }
}

#[async_trait]
impl DockerBlobStorePort for FilesystemDockerBlobStore {
    async fn write(&self, digest: &Digest, bytes: &[u8]) -> Result<(), DomainError> {
        let hex = Self::hex_part(digest)?;
        let storage_key = Self::storage_key(hex);
        let target = self.root.join(&storage_key);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await.infra_err()?;
        }
        let tmp_path = target.with_file_name(format!("{hex}.tmp-{}", Uuid::new_v4()));
        fs::write(&tmp_path, bytes).await.infra_err()?;
        fs::rename(&tmp_path, &target).await.infra_err()?;

        // A re-write of an identical digest must not reset reference_count.
        sqlx::query!(
            "INSERT INTO docker_blobs (digest, size_bytes, storage_key, reference_count) VALUES ($1, $2, $3, 0) \
             ON CONFLICT (digest) DO NOTHING",
            digest.as_str(),
            bytes.len() as i64,
            storage_key,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn adopt_staged_file(&self, digest: &Digest, staging_path: &str, size_bytes: u64) -> Result<(), DomainError> {
        let hex = Self::hex_part(digest)?;
        let storage_key = Self::storage_key(hex);
        let target = self.root.join(&storage_key);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await.infra_err()?;
        }
        fs::rename(staging_path, &target).await.infra_err()?;

        // A re-adoption of an identical digest must not reset reference_count.
        sqlx::query!(
            "INSERT INTO docker_blobs (digest, size_bytes, storage_key, reference_count) VALUES ($1, $2, $3, 0) \
             ON CONFLICT (digest) DO NOTHING",
            digest.as_str(),
            size_bytes as i64,
            storage_key,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn read(&self, digest: &Digest) -> Result<Vec<u8>, DomainError> {
        let row = sqlx::query!("SELECT storage_key FROM docker_blobs WHERE digest = $1", digest.as_str())
            .fetch_optional(&self.pool)
            .await
            .infra_err()?
            .ok_or_else(|| DomainError::Infrastructure(format!("blob not found: {}", digest.as_str())))?;
        fs::read(self.root.join(row.storage_key)).await.infra_err()
    }

    async fn read_stream(&self, digest: &Digest) -> Result<ByteStream, DomainError> {
        let row = sqlx::query!("SELECT storage_key FROM docker_blobs WHERE digest = $1", digest.as_str())
            .fetch_optional(&self.pool)
            .await
            .infra_err()?
            .ok_or_else(|| DomainError::Infrastructure(format!("blob not found: {}", digest.as_str())))?;
        let file = fs::File::open(self.root.join(row.storage_key)).await.infra_err()?;
        Ok(Box::pin(ReaderStream::new(file).map_err(|e| DomainError::Infrastructure(e.to_string()))))
    }

    async fn link_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO docker_repository_blobs (package_repository_id, blob_digest) VALUES ($1, $2) \
             ON CONFLICT (package_repository_id, blob_digest) DO NOTHING",
            repository_id,
            digest.as_str(),
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn is_uploaded_to_repository(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError> {
        let row = sqlx::query!(
            "SELECT EXISTS(SELECT 1 FROM docker_repository_blobs WHERE package_repository_id = $1 AND blob_digest = $2) AS \"exists!\"",
            repository_id,
            digest.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .infra_err()?;
        Ok(row.exists)
    }

    async fn exists(&self, digest: &Digest) -> Result<bool, DomainError> {
        let row = sqlx::query!("SELECT EXISTS(SELECT 1 FROM docker_blobs WHERE digest = $1) AS \"exists!\"", digest.as_str())
            .fetch_one(&self.pool)
            .await
            .infra_err()?;
        Ok(row.exists)
    }

    async fn size_if_exists(&self, digest: &Digest) -> Result<Option<u64>, DomainError> {
        let row = sqlx::query!("SELECT size_bytes FROM docker_blobs WHERE digest = $1", digest.as_str())
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        Ok(row.map(|r| r.size_bytes as u64))
    }

    async fn existing_digests(&self, digests: &[Digest]) -> Result<std::collections::HashSet<String>, DomainError> {
        if digests.is_empty() {
            return Ok(std::collections::HashSet::new());
        }
        let digest_strs: Vec<String> = digests.iter().map(|d| d.as_str().to_string()).collect();
        let rows = sqlx::query!("SELECT digest FROM docker_blobs WHERE digest = ANY($1)", &digest_strs)
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        Ok(rows.into_iter().map(|r| r.digest).collect())
    }

    async fn sum_sizes(&self, digests: &[Digest]) -> Result<u64, DomainError> {
        if digests.is_empty() {
            return Ok(0);
        }
        let digest_strs: Vec<String> = digests.iter().map(|d| d.as_str().to_string()).collect();
        let total: Option<i64> = sqlx::query_scalar!("SELECT SUM(size_bytes)::BIGINT FROM docker_blobs WHERE digest = ANY($1)", &digest_strs)
            .fetch_one(&self.pool)
            .await
            .infra_err()?;
        Ok(total.unwrap_or(0) as u64)
    }

    async fn increment_ref(&self, digest: &Digest) -> Result<(), DomainError> {
        sqlx::query!("UPDATE docker_blobs SET reference_count = reference_count + 1 WHERE digest = $1", digest.as_str())
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn increment_ref_all(&self, digests: &[Digest]) -> Result<(), DomainError> {
        if digests.is_empty() {
            return Ok(());
        }
        let digest_strs: Vec<String> = digests.iter().map(|d| d.as_str().to_string()).collect();
        sqlx::query!("UPDATE docker_blobs SET reference_count = reference_count + 1 WHERE digest = ANY($1)", &digest_strs)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn decrement_ref_and_delete_if_zero(&self, digest: &Digest) -> Result<bool, DomainError> {
        // One transaction, or a concurrent push on the same shared blob could sneak in between.
        let mut tx = self.pool.begin().await.infra_err()?;
        let row = sqlx::query!(
            "UPDATE docker_blobs SET reference_count = reference_count - 1 WHERE digest = $1 RETURNING reference_count, storage_key",
            digest.as_str()
        )
        .fetch_optional(&mut *tx)
        .await
        .infra_err()?;
        let Some(row) = row else { return Ok(false) };
        if row.reference_count > 0 {
            tx.commit().await.infra_err()?;
            return Ok(false);
        }
        // A concurrent push can still land a new reference here — that's not an error, just "still referenced".
        match sqlx::query!("DELETE FROM docker_blobs WHERE digest = $1", digest.as_str()).execute(&mut *tx).await {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_foreign_key_violation() => {
                tx.rollback().await.infra_err()?;
                return Ok(false);
            }
            Err(e) => return Err(DomainError::Infrastructure(e.to_string())),
        }
        tx.commit().await.infra_err()?;
        let _ = fs::remove_file(self.root.join(&row.storage_key)).await;
        Ok(true)
    }

    async fn used_bytes_for_repository(&self, repository_id: Uuid) -> Result<u64, DomainError> {
        let total: Option<i64> = sqlx::query_scalar!(
            "SELECT SUM(db.size_bytes)::BIGINT FROM docker_blobs db \
             WHERE db.digest IN ( \
                 SELECT DISTINCT dmb.blob_digest FROM docker_manifest_blobs dmb \
                 JOIN docker_manifests dm ON dm.id = dmb.manifest_id \
                 WHERE dm.package_repository_id = $1 \
             )",
            repository_id
        )
        .fetch_one(&self.pool)
        .await
        .infra_err()?;
        Ok(total.unwrap_or(0) as u64)
    }

    async fn used_bytes_for_repositories(&self, repository_ids: &[Uuid]) -> Result<std::collections::HashMap<Uuid, u64>, DomainError> {
        let rows = sqlx::query!(
            "SELECT repository_id, SUM(db.size_bytes)::BIGINT AS total_bytes FROM ( \
                 SELECT DISTINCT dm.package_repository_id AS repository_id, dmb.blob_digest \
                 FROM docker_manifests dm \
                 JOIN docker_manifest_blobs dmb ON dmb.manifest_id = dm.id \
                 WHERE dm.package_repository_id = ANY($1) \
             ) distinct_blobs \
             JOIN docker_blobs db ON db.digest = distinct_blobs.blob_digest \
             GROUP BY repository_id",
            repository_ids
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().map(|row| (row.repository_id, row.total_bytes.unwrap_or(0) as u64)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn writes_then_reads_back_the_same_bytes(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let digest = Digest::of(b"layer-bytes");
        store.write(&digest, b"layer-bytes").await.unwrap();

        assert_eq!(store.read(&digest).await.unwrap(), b"layer-bytes");
        assert!(store.exists(&digest).await.unwrap());
    }

    #[sqlx::test]
    async fn writing_the_same_digest_twice_is_a_safe_no_op(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let digest = Digest::of(b"layer-bytes");
        store.write(&digest, b"layer-bytes").await.unwrap();
        store.increment_ref(&digest).await.unwrap();
        store.write(&digest, b"layer-bytes").await.unwrap();
        store.increment_ref(&digest).await.unwrap();

        assert!(!store.decrement_ref_and_delete_if_zero(&digest).await.unwrap());
        assert!(store.exists(&digest).await.unwrap());
    }

    #[sqlx::test]
    async fn decrementing_to_zero_deletes_the_row_and_the_file(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let digest = Digest::of(b"layer-bytes");
        store.write(&digest, b"layer-bytes").await.unwrap();
        store.increment_ref(&digest).await.unwrap();

        assert!(store.decrement_ref_and_delete_if_zero(&digest).await.unwrap());
        assert!(!store.exists(&digest).await.unwrap());
        assert!(store.read(&digest).await.is_err());
    }

    #[sqlx::test]
    async fn a_blob_with_two_references_survives_one_decrement(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let digest = Digest::of(b"shared-base-layer");
        store.write(&digest, b"shared-base-layer").await.unwrap();
        store.increment_ref(&digest).await.unwrap();
        store.increment_ref(&digest).await.unwrap();

        assert!(!store.decrement_ref_and_delete_if_zero(&digest).await.unwrap());
        assert!(store.exists(&digest).await.unwrap());
    }

    #[sqlx::test]
    async fn exists_reports_false_for_an_unwritten_digest(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        assert!(!store.exists(&Digest::of(b"never-written")).await.unwrap());
    }

    #[sqlx::test]
    async fn size_if_exists_returns_the_real_byte_length_without_reading_the_blob(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let digest = Digest::of(b"layer-bytes");
        store.write(&digest, b"layer-bytes").await.unwrap();

        assert_eq!(store.size_if_exists(&digest).await.unwrap(), Some(b"layer-bytes".len() as u64));
    }

    #[sqlx::test]
    async fn existing_digests_returns_only_the_ones_actually_present(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let present = Digest::of(b"present-blob");
        let missing = Digest::of(b"missing-blob");
        store.write(&present, b"present-blob").await.unwrap();

        let found = store.existing_digests(&[present.clone(), missing]).await.unwrap();

        assert_eq!(found, std::collections::HashSet::from([present.as_str().to_string()]));
    }

    #[sqlx::test]
    async fn sum_sizes_adds_only_the_digests_that_exist(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let a = Digest::of(b"aaaaa"); // 5 bytes
        let b = Digest::of(b"bbbbbbbbbb"); // 10 bytes
        let missing = Digest::of(b"never-written");
        store.write(&a, b"aaaaa").await.unwrap();
        store.write(&b, b"bbbbbbbbbb").await.unwrap();

        let total = store.sum_sizes(&[a, b, missing]).await.unwrap();

        assert_eq!(total, 15);
    }

    #[sqlx::test]
    async fn increment_ref_all_bumps_every_given_digest_by_exactly_one(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        let a = Digest::of(b"blob-a");
        let b = Digest::of(b"blob-b");
        store.write(&a, b"blob-a").await.unwrap();
        store.write(&b, b"blob-b").await.unwrap();

        store.increment_ref_all(&[a.clone(), b.clone()]).await.unwrap();

        // Each started at 0 — one decrement reaching exactly 0 proves the batched bump was +1, not 0 or +2.
        assert!(store.decrement_ref_and_delete_if_zero(&a).await.unwrap());
        assert!(store.decrement_ref_and_delete_if_zero(&b).await.unwrap());
    }

    #[sqlx::test]
    async fn size_if_exists_returns_none_for_an_unwritten_digest(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool, dir.path());
        assert_eq!(store.size_if_exists(&Digest::of(b"never-written")).await.unwrap(), None);
    }

    async fn seed_repository(pool: &sqlx::PgPool) -> Uuid {
        let repository_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, version, created_at, updated_at) \
             VALUES ($1, $2, $3, 'docker', 'hosted', 1, now(), now())",
            repository_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            format!("repo-{repository_id}"),
        )
        .execute(pool)
        .await
        .unwrap();
        repository_id
    }

    async fn seed_manifest_with_blobs(pool: &sqlx::PgPool, repository_id: Uuid, blob_digests: &[&Digest]) {
        let manifest_id = Uuid::new_v4();
        let manifest_digest = Digest::of(manifest_id.as_bytes());
        sqlx::query!(
            "INSERT INTO docker_manifests (id, package_repository_id, image_name, digest, media_type, body, created_at) \
             VALUES ($1, $2, 'myimage', $3, 'application/vnd.docker.distribution.manifest.v2+json', '{}', now())",
            manifest_id,
            repository_id,
            manifest_digest.as_str(),
        )
        .execute(pool)
        .await
        .unwrap();
        for digest in blob_digests {
            sqlx::query!(
                "INSERT INTO docker_manifest_blobs (manifest_id, blob_digest) VALUES ($1, $2)",
                manifest_id,
                digest.as_str(),
            )
            .execute(pool)
            .await
            .unwrap();
        }
    }

    #[sqlx::test]
    async fn used_bytes_for_repository_sums_distinct_blobs_referenced_by_its_manifests(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool.clone(), dir.path());
        let repository_id = seed_repository(&pool).await;

        let base_layer = Digest::of(b"base-layer");
        let app_layer = Digest::of(b"app-layer");
        store.write(&base_layer, b"base-layer").await.unwrap(); // 10 bytes
        store.write(&app_layer, b"app-layer-content").await.unwrap(); // 17 bytes

        seed_manifest_with_blobs(&pool, repository_id, &[&base_layer, &app_layer]).await;
        seed_manifest_with_blobs(&pool, repository_id, &[&base_layer]).await;

        let used = store.used_bytes_for_repository(repository_id).await.unwrap();
        assert_eq!(used, b"base-layer".len() as u64 + b"app-layer-content".len() as u64);
    }

    #[sqlx::test]
    async fn used_bytes_for_repository_ignores_manifests_in_other_repositories(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool.clone(), dir.path());
        let repository_id = seed_repository(&pool).await;
        let other_repository_id = seed_repository(&pool).await;

        let digest = Digest::of(b"only-in-other-repo");
        store.write(&digest, b"only-in-other-repo").await.unwrap();
        seed_manifest_with_blobs(&pool, other_repository_id, &[&digest]).await;

        assert_eq!(store.used_bytes_for_repository(repository_id).await.unwrap(), 0);
    }

    #[sqlx::test]
    async fn used_bytes_for_repository_is_zero_for_a_repository_with_no_manifests(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemDockerBlobStore::new(pool.clone(), dir.path());
        let repository_id = seed_repository(&pool).await;

        assert_eq!(store.used_bytes_for_repository(repository_id).await.unwrap(), 0);
    }
}
