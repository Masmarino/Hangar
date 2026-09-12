use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerManifestRepositoryPort, DockerMediaType};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresDockerManifestRepository {
    pool: PgPool,
}

impl PostgresDockerManifestRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct ManifestRow {
    id: Uuid,
    package_repository_id: Uuid,
    image_name: String,
    digest: String,
    media_type: String,
    body: Vec<u8>,
    created_at: DateTime<Utc>,
}

impl ManifestRow {
    fn into_domain(self) -> Result<DockerManifest, DomainError> {
        Ok(DockerManifest {
            id: self.id,
            package_repository_id: self.package_repository_id,
            image_name: DockerImageName::parse(&self.image_name)?,
            digest: Digest::parse(&self.digest)?,
            media_type: DockerMediaType::parse(&self.media_type)?,
            body: self.body,
            created_at: self.created_at,
        })
    }
}

#[async_trait]
impl DockerManifestRepositoryPort for PostgresDockerManifestRepository {
    async fn find_manifest_by_tag(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str) -> Result<Option<DockerManifest>, DomainError> {
        let row = sqlx::query_as!(
            ManifestRow,
            "SELECT m.id, m.package_repository_id, m.image_name, m.digest, m.media_type, m.body, m.created_at \
             FROM docker_manifests m JOIN docker_tags t ON t.manifest_id = m.id \
             WHERE t.package_repository_id = $1 AND t.image_name = $2 AND t.tag = $3",
            repository_id,
            image_name.as_str(),
            tag
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(ManifestRow::into_domain).transpose()
    }

    async fn find_manifest_by_digest(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest) -> Result<Option<DockerManifest>, DomainError> {
        let row = sqlx::query_as!(
            ManifestRow,
            "SELECT id, package_repository_id, image_name, digest, media_type, body, created_at FROM docker_manifests \
             WHERE package_repository_id = $1 AND image_name = $2 AND digest = $3",
            repository_id,
            image_name.as_str(),
            digest.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(ManifestRow::into_domain).transpose()
    }

    async fn insert_manifest(&self, manifest: &DockerManifest, blob_digests: &[Digest]) -> Result<(Uuid, bool), DomainError> {
        // Transactional so a crash mid-insert can't leave the manifest row without its blob rows.
        let mut tx = self.pool.begin().await.infra_err()?;

        // Idempotent for a re-pushed byte-identical manifest. `RETURNING id` distinguishes "inserted" from "already present" so the caller gets the real, persisted id either way.
        let inserted = sqlx::query!(
            "INSERT INTO docker_manifests (id, package_repository_id, image_name, digest, media_type, body, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (package_repository_id, image_name, digest) DO NOTHING \
             RETURNING id",
            manifest.id,
            manifest.package_repository_id,
            manifest.image_name.as_str(),
            manifest.digest.as_str(),
            manifest.media_type.as_str(),
            manifest.body,
            manifest.created_at,
        )
        .fetch_optional(&mut *tx)
        .await
        .infra_err()?;

        let Some(inserted) = inserted else {
            let existing = sqlx::query!(
                "SELECT id FROM docker_manifests WHERE package_repository_id = $1 AND image_name = $2 AND digest = $3",
                manifest.package_repository_id,
                manifest.image_name.as_str(),
                manifest.digest.as_str(),
            )
            .fetch_one(&mut *tx)
            .await
            .infra_err()?;
            tx.commit().await.infra_err()?;
            return Ok((existing.id, false));
        };

        let blob_digest_strs: Vec<&str> = blob_digests.iter().map(|d| d.as_str()).collect();
        sqlx::query!(
            "INSERT INTO docker_manifest_blobs (manifest_id, blob_digest) SELECT $1, * FROM UNNEST($2::text[])",
            inserted.id,
            &blob_digest_strs as &[&str],
        )
        .execute(&mut *tx)
        .await
        .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok((inserted.id, true))
    }

    async fn insert_manifest_list_members(&self, list_manifest_id: Uuid, member_digests: &[Digest]) -> Result<(), DomainError> {
        // Transactional and idempotent: a retry after a partial failure must not PK-violate.
        let mut tx = self.pool.begin().await.infra_err()?;
        let member_digest_strs: Vec<&str> = member_digests.iter().map(|d| d.as_str()).collect();
        sqlx::query!(
            "INSERT INTO docker_manifest_list_members (list_manifest_id, member_digest) SELECT $1, * FROM UNNEST($2::text[]) \
             ON CONFLICT (list_manifest_id, member_digest) DO NOTHING",
            list_manifest_id,
            &member_digest_strs as &[&str],
        )
        .execute(&mut *tx)
        .await
        .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok(())
    }

    async fn list_manifest_blob_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError> {
        let rows = sqlx::query!("SELECT blob_digest FROM docker_manifest_blobs WHERE manifest_id = $1", manifest_id)
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        rows.into_iter().map(|r| Digest::parse(&r.blob_digest)).collect()
    }

    async fn list_manifest_list_member_digests(&self, manifest_id: Uuid) -> Result<Vec<Digest>, DomainError> {
        let rows = sqlx::query!("SELECT member_digest FROM docker_manifest_list_members WHERE list_manifest_id = $1", manifest_id)
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        rows.into_iter().map(|r| Digest::parse(&r.member_digest)).collect()
    }

    async fn set_tag(&self, repository_id: Uuid, image_name: &DockerImageName, tag: &str, manifest_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO docker_tags (package_repository_id, image_name, tag, manifest_id, updated_at) VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (package_repository_id, image_name, tag) DO UPDATE SET manifest_id = $4, updated_at = now()",
            repository_id,
            image_name.as_str(),
            tag,
            manifest_id,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn delete_manifest(&self, repository_id: Uuid, image_name: &DockerImageName, digest: &Digest) -> Result<(), DomainError> {
        sqlx::query!(
            "DELETE FROM docker_manifests WHERE package_repository_id = $1 AND image_name = $2 AND digest = $3",
            repository_id,
            image_name.as_str(),
            digest.as_str(),
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn list_tags(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<String>, DomainError> {
        let rows = sqlx::query!(
            "SELECT tag FROM docker_tags WHERE package_repository_id = $1 AND image_name = $2 ORDER BY tag",
            repository_id,
            image_name.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().map(|r| r.tag).collect())
    }

    async fn list_repository_image_names(&self, repository_id: Uuid) -> Result<Vec<DockerImageName>, DomainError> {
        // An untagged manifest reachable only by digest doesn't surface here.
        let rows = sqlx::query!(
            "SELECT DISTINCT image_name FROM docker_tags WHERE package_repository_id = $1 ORDER BY image_name",
            repository_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(|r| DockerImageName::parse(&r.image_name)).collect()
    }

    async fn list_image_names_for_repositories(&self, repository_ids: &[Uuid]) -> Result<Vec<(Uuid, DockerImageName)>, DomainError> {
        let rows = sqlx::query!(
            "SELECT DISTINCT package_repository_id, image_name FROM docker_tags WHERE package_repository_id = ANY($1) ORDER BY package_repository_id, image_name",
            repository_ids
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        // An unparseable row is skipped rather than poisoning the whole batched result.
        Ok(rows.into_iter().filter_map(|r| DockerImageName::parse(&r.image_name).ok().map(|name| (r.package_repository_id, name))).collect())
    }

    async fn list_all_tags_for_repository(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String)>, DomainError> {
        let rows = sqlx::query!(
            "SELECT image_name, tag FROM docker_tags WHERE package_repository_id = $1 ORDER BY image_name, tag",
            repository_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().filter_map(|r| DockerImageName::parse(&r.image_name).ok().map(|name| (name, r.tag))).collect())
    }

    async fn list_latest_manifest_id_per_image(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, Uuid)>, DomainError> {
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (image_name) image_name, manifest_id \
             FROM docker_tags WHERE package_repository_id = $1 \
             ORDER BY image_name, updated_at DESC",
            repository_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().filter_map(|r| DockerImageName::parse(&r.image_name).ok().map(|name| (name, r.manifest_id))).collect())
    }

    async fn list_distinct_digests_for_image(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<Digest>, DomainError> {
        let rows = sqlx::query!(
            "SELECT DISTINCT m.digest FROM docker_manifests m JOIN docker_tags t ON t.manifest_id = m.id \
             WHERE t.package_repository_id = $1 AND t.image_name = $2",
            repository_id,
            image_name.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(|r| Digest::parse(&r.digest)).collect()
    }

    async fn list_tag_manifest_summaries(&self, repository_id: Uuid, image_name: &DockerImageName) -> Result<Vec<(String, Digest, DockerMediaType, DateTime<Utc>)>, DomainError> {
        let rows = sqlx::query!(
            "SELECT t.tag, m.digest, m.media_type, m.created_at \
             FROM docker_tags t JOIN docker_manifests m ON m.id = t.manifest_id \
             WHERE t.package_repository_id = $1 AND t.image_name = $2 ORDER BY t.tag",
            repository_id,
            image_name.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(|r| Ok((r.tag, Digest::parse(&r.digest)?, DockerMediaType::parse(&r.media_type)?, r.created_at))).collect()
    }

    async fn list_repository_tag_manifest_summaries(&self, repository_id: Uuid) -> Result<Vec<(DockerImageName, String, Digest, DockerMediaType, DateTime<Utc>)>, DomainError> {
        let rows = sqlx::query!(
            "SELECT t.image_name, t.tag, m.digest, m.media_type, m.created_at \
             FROM docker_tags t JOIN docker_manifests m ON m.id = t.manifest_id \
             WHERE t.package_repository_id = $1 ORDER BY t.image_name, t.tag",
            repository_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter()
            .map(|r| Ok((DockerImageName::parse(&r.image_name)?, r.tag, Digest::parse(&r.digest)?, DockerMediaType::parse(&r.media_type)?, r.created_at)))
            .collect()
    }

    async fn blob_is_reachable(&self, repository_id: Uuid, digest: &Digest) -> Result<bool, DomainError> {
        let row = sqlx::query!(
            "SELECT EXISTS( \
                 SELECT 1 FROM docker_manifest_blobs dmb \
                 JOIN docker_manifests dm ON dm.id = dmb.manifest_id \
                 WHERE dm.package_repository_id = $1 AND dmb.blob_digest = $2 \
             ) AS \"exists!\"",
            repository_id,
            digest.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .infra_err()?;
        Ok(row.exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::docker_registry::DockerMediaType;

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

    // Postgres enforces the FK to docker_blobs, unlike the in-memory fake.
    async fn seed_blob(pool: &sqlx::PgPool, digest: &Digest) {
        sqlx::query!(
            "INSERT INTO docker_blobs (digest, size_bytes, storage_key, reference_count, created_at) \
             VALUES ($1, 0, $1, 0, now())",
            digest.as_str(),
        )
        .execute(pool)
        .await
        .unwrap();
    }

    fn sample_manifest(repository_id: Uuid, image_name: &DockerImageName) -> DockerManifest {
        DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            image_name: image_name.clone(),
            digest: Digest::of(b"manifest-bytes"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: br#"{"schemaVersion": 2}"#.to_vec(),
            created_at: chrono::Utc::now(),
        }
    }

    #[sqlx::test]
    async fn inserts_a_manifest_with_its_blobs_and_finds_it_by_digest(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);
        let blob_digest = Digest::of(b"layer-bytes");
        seed_blob(&pool, &blob_digest).await;
        repo.insert_manifest(&manifest, &[blob_digest.clone()]).await.unwrap();

        let found = repo.find_manifest_by_digest(repository_id, &image_name, &manifest.digest).await.unwrap().unwrap();
        assert_eq!(found.id, manifest.id);
        assert_eq!(found.media_type, DockerMediaType::DockerV2Manifest);
        assert_eq!(found.body, manifest.body);

        let blob_digests = repo.list_manifest_blob_digests(manifest.id).await.unwrap();
        assert_eq!(blob_digests, vec![blob_digest]);
    }

    #[sqlx::test]
    async fn re_inserting_the_same_digest_is_a_no_op_not_an_error(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);
        let blob_digest = Digest::of(b"layer-bytes");
        seed_blob(&pool, &blob_digest).await;
        let (first_id, first_inserted) = repo.insert_manifest(&manifest, &[blob_digest.clone()]).await.unwrap();
        assert_eq!(first_id, manifest.id);
        assert!(first_inserted);

        // A second insert of the identical (repository, image, digest) must return the pre-existing row's id, not the caller's own unpersisted one.
        let mut second_attempt = sample_manifest(repository_id, &image_name);
        second_attempt.id = Uuid::new_v4();
        assert_ne!(second_attempt.id, manifest.id);
        let (second_id, second_inserted) = repo.insert_manifest(&second_attempt, &[blob_digest.clone()]).await.unwrap();
        assert_eq!(second_id, manifest.id, "insert_manifest must return the pre-existing row's id on conflict, not the caller's own unpersisted id");
        assert!(!second_inserted, "a conflict must report false, not true — callers rely on this to avoid double-counting blob refs");

        assert_eq!(repo.list_manifest_blob_digests(manifest.id).await.unwrap(), vec![blob_digest]);
    }

    #[sqlx::test]
    async fn setting_a_tag_makes_the_manifest_findable_by_tag(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);
        repo.insert_manifest(&manifest, &[]).await.unwrap();

        repo.set_tag(repository_id, &image_name, "latest", manifest.id).await.unwrap();

        let found = repo.find_manifest_by_tag(repository_id, &image_name, "latest").await.unwrap().unwrap();
        assert_eq!(found.id, manifest.id);
        assert!(repo.find_manifest_by_tag(repository_id, &image_name, "missing").await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn re_tagging_moves_the_tag_to_the_new_manifest(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let first = sample_manifest(repository_id, &image_name);
        repo.insert_manifest(&first, &[]).await.unwrap();
        repo.set_tag(repository_id, &image_name, "latest", first.id).await.unwrap();
        let mut second = sample_manifest(repository_id, &image_name);
        second.digest = Digest::of(b"a-different-manifest-body");
        repo.insert_manifest(&second, &[]).await.unwrap();

        repo.set_tag(repository_id, &image_name, "latest", second.id).await.unwrap();

        let found = repo.find_manifest_by_tag(repository_id, &image_name, "latest").await.unwrap().unwrap();
        assert_eq!(found.id, second.id);
    }

    #[sqlx::test]
    async fn inserts_and_lists_manifest_list_members(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let mut list_manifest = sample_manifest(repository_id, &image_name);
        list_manifest.media_type = DockerMediaType::OciIndex;
        repo.insert_manifest(&list_manifest, &[]).await.unwrap();
        let member_a = Digest::of(b"amd64-manifest");
        let member_b = Digest::of(b"arm64-manifest");

        repo.insert_manifest_list_members(list_manifest.id, &[member_a.clone(), member_b.clone()]).await.unwrap();

        let mut members = repo.list_manifest_list_member_digests(list_manifest.id).await.unwrap();
        members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut expected = vec![member_a, member_b];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(members, expected);
    }

    #[sqlx::test]
    async fn retrying_insert_manifest_list_members_after_a_partial_success_does_not_fail(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let mut list_manifest = sample_manifest(repository_id, &image_name);
        list_manifest.media_type = DockerMediaType::OciIndex;
        repo.insert_manifest(&list_manifest, &[]).await.unwrap();
        let member_a = Digest::of(b"amd64-manifest");
        let member_b = Digest::of(b"arm64-manifest");

        // Simulates a client retry after a member was already recorded on a prior attempt.
        repo.insert_manifest_list_members(list_manifest.id, &[member_a.clone()]).await.unwrap();
        repo.insert_manifest_list_members(list_manifest.id, &[member_a.clone(), member_b.clone()]).await.unwrap();

        let mut members = repo.list_manifest_list_member_digests(list_manifest.id).await.unwrap();
        members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        let mut expected = vec![member_a, member_b];
        expected.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(members, expected);
    }

    #[sqlx::test]
    async fn deleting_a_manifest_removes_it_and_its_tag(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);
        repo.insert_manifest(&manifest, &[]).await.unwrap();
        repo.set_tag(repository_id, &image_name, "latest", manifest.id).await.unwrap();

        repo.delete_manifest(repository_id, &image_name, &manifest.digest).await.unwrap();

        assert!(repo.find_manifest_by_digest(repository_id, &image_name, &manifest.digest).await.unwrap().is_none());
        assert!(repo.find_manifest_by_tag(repository_id, &image_name, "latest").await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn lists_sorted_tags_for_one_image_and_deduplicated_catalog_names(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("myimage").unwrap();
        let manifest = sample_manifest(repository_id, &image_name);
        repo.insert_manifest(&manifest, &[]).await.unwrap();
        repo.set_tag(repository_id, &image_name, "v2", manifest.id).await.unwrap();
        repo.set_tag(repository_id, &image_name, "v1", manifest.id).await.unwrap();

        assert_eq!(repo.list_tags(repository_id, &image_name).await.unwrap(), vec!["v1".to_string(), "v2".to_string()]);
        assert_eq!(repo.list_repository_image_names(repository_id).await.unwrap(), vec![image_name]);
    }

    #[sqlx::test]
    async fn list_all_tags_for_repository_batches_every_images_tags_in_one_query(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let app = DockerImageName::parse("app").unwrap();
        let worker = DockerImageName::parse("worker").unwrap();
        let app_manifest = sample_manifest(repository_id, &app);
        let worker_manifest = sample_manifest(repository_id, &worker);
        repo.insert_manifest(&app_manifest, &[]).await.unwrap();
        repo.insert_manifest(&worker_manifest, &[]).await.unwrap();
        repo.set_tag(repository_id, &app, "latest", app_manifest.id).await.unwrap();
        repo.set_tag(repository_id, &app, "v1", app_manifest.id).await.unwrap();
        repo.set_tag(repository_id, &worker, "latest", worker_manifest.id).await.unwrap();

        let pairs = repo.list_all_tags_for_repository(repository_id).await.unwrap();

        assert_eq!(
            pairs,
            vec![(app.clone(), "latest".to_string()), (app, "v1".to_string()), (worker, "latest".to_string())]
        );
    }

    #[sqlx::test]
    async fn list_latest_manifest_id_per_image_batches_across_every_image_in_the_repository(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let app = DockerImageName::parse("app").unwrap();
        let worker = DockerImageName::parse("worker").unwrap();
        let app_manifest = sample_manifest(repository_id, &app);
        let worker_manifest = sample_manifest(repository_id, &worker);
        repo.insert_manifest(&app_manifest, &[]).await.unwrap();
        repo.insert_manifest(&worker_manifest, &[]).await.unwrap();
        repo.set_tag(repository_id, &app, "latest", app_manifest.id).await.unwrap();
        repo.set_tag(repository_id, &worker, "latest", worker_manifest.id).await.unwrap();

        let mut latest = repo.list_latest_manifest_id_per_image(repository_id).await.unwrap();
        latest.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));

        assert_eq!(latest, vec![(app, app_manifest.id), (worker, worker_manifest.id)]);
    }

    #[sqlx::test]
    async fn list_latest_manifest_id_per_image_follows_the_most_recently_updated_tag(pool: sqlx::PgPool) {
        let repo = PostgresDockerManifestRepository::new(pool.clone());
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, repository_id).await;
        let image_name = DockerImageName::parse("app").unwrap();
        let old_manifest = sample_manifest(repository_id, &image_name);
        let mut new_manifest = sample_manifest(repository_id, &image_name);
        new_manifest.digest = Digest::of(b"a different manifest body");
        repo.insert_manifest(&old_manifest, &[]).await.unwrap();
        repo.insert_manifest(&new_manifest, &[]).await.unwrap();
        repo.set_tag(repository_id, &image_name, "1.0.0", old_manifest.id).await.unwrap();
        repo.set_tag(repository_id, &image_name, "latest", new_manifest.id).await.unwrap();
        // Force a deterministic ordering rather than relying on two `now()` calls landing microseconds apart.
        sqlx::query!(
            "UPDATE docker_tags SET updated_at = now() - interval '1 hour' WHERE package_repository_id = $1 AND tag = '1.0.0'",
            repository_id
        )
        .execute(&pool)
        .await
        .unwrap();

        let latest = repo.list_latest_manifest_id_per_image(repository_id).await.unwrap();

        assert_eq!(latest, vec![(image_name, new_manifest.id)]);
    }
}
