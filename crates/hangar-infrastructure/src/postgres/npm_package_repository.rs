use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::npm_package::{
    NpmDistTag, NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageRepositoryPort, NpmPackageVersion, NpmVersion,
};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresNpmPackageRepository {
    pool: PgPool,
}

impl PostgresNpmPackageRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct PackageRow {
    id: Uuid,
    package_repository_id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    metadata_fetched_at: Option<DateTime<Utc>>,
    cached_metadata: Option<serde_json::Value>,
}

impl PackageRow {
    fn into_domain(self) -> Result<NpmPackage, DomainError> {
        Ok(NpmPackage {
            id: self.id,
            package_repository_id: self.package_repository_id,
            name: NpmPackageName::parse(&self.name)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            metadata_fetched_at: self.metadata_fetched_at,
            cached_metadata: self.cached_metadata,
        })
    }
}

/// Like `PackageRow` but skips `cached_metadata` — can be huge, and search() never reads it.
struct SearchRow {
    id: Uuid,
    package_repository_id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SearchRow {
    fn into_domain(self) -> Result<NpmPackage, DomainError> {
        Ok(NpmPackage {
            id: self.id,
            package_repository_id: self.package_repository_id,
            name: NpmPackageName::parse(&self.name)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            metadata_fetched_at: None,
            cached_metadata: None,
        })
    }
}

/// Backs `list_versions_for_packages` — same idea as `SearchRow`, no `manifest`.
struct VersionSummaryRow {
    npm_package_id: Uuid,
    version: String,
    tarball_size_bytes: i64,
    deprecated: bool,
    published_at: DateTime<Utc>,
}

impl VersionSummaryRow {
    fn into_domain(self) -> Result<hangar_domain::npm_package::NpmPackageVersionSummary, DomainError> {
        Ok(hangar_domain::npm_package::NpmPackageVersionSummary {
            npm_package_id: self.npm_package_id,
            version: NpmVersion::parse(&self.version)?,
            tarball_size_bytes: self.tarball_size_bytes,
            deprecated: self.deprecated,
            published_at: self.published_at,
        })
    }
}

struct VersionRow {
    id: Uuid,
    npm_package_id: Uuid,
    version: String,
    manifest: serde_json::Value,
    shasum: String,
    integrity: String,
    tarball_storage_key: String,
    tarball_size_bytes: i64,
    deprecated: bool,
    deprecated_message: Option<String>,
    published_by: Option<Uuid>,
    published_at: DateTime<Utc>,
    origin: String,
}

impl VersionRow {
    fn into_domain(self) -> Result<NpmPackageVersion, DomainError> {
        Ok(NpmPackageVersion {
            id: self.id,
            npm_package_id: self.npm_package_id,
            version: NpmVersion::parse(&self.version)?,
            manifest: self.manifest,
            shasum: self.shasum,
            integrity: self.integrity,
            tarball_storage_key: self.tarball_storage_key,
            tarball_size_bytes: self.tarball_size_bytes,
            deprecated: self.deprecated,
            deprecated_message: self.deprecated_message,
            published_by: self.published_by,
            published_at: self.published_at,
            origin: match self.origin.as_str() {
                "local" => NpmPackageOrigin::Local,
                _ => NpmPackageOrigin::ProxyCache,
            },
        })
    }
}

#[async_trait]
impl NpmPackageRepositoryPort for PostgresNpmPackageRepository {
    async fn find_package(&self, repository_id: Uuid, name: &NpmPackageName) -> Result<Option<NpmPackage>, DomainError> {
        let row = sqlx::query_as!(
            PackageRow,
            "SELECT id, package_repository_id, name, created_at, updated_at, metadata_fetched_at, cached_metadata \
             FROM npm_packages WHERE package_repository_id = $1 AND name = $2",
            repository_id,
            name.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(PackageRow::into_domain).transpose()
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<NpmPackage>, DomainError> {
        let row = sqlx::query_as!(
            PackageRow,
            "SELECT id, package_repository_id, name, created_at, updated_at, metadata_fetched_at, cached_metadata \
             FROM npm_packages WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(PackageRow::into_domain).transpose()
    }

    async fn create_package(&self, package: &NpmPackage) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO npm_packages (id, package_repository_id, name, created_at, updated_at, metadata_fetched_at, cached_metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            package.id,
            package.package_repository_id,
            package.name.as_str(),
            package.created_at,
            package.updated_at,
            package.metadata_fetched_at,
            package.cached_metadata,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn touch_metadata_fetched_at(&self, npm_package_id: Uuid, fetched_at: DateTime<Utc>) -> Result<(), DomainError> {
        sqlx::query!("UPDATE npm_packages SET metadata_fetched_at = $2, updated_at = now() WHERE id = $1", npm_package_id, fetched_at)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn list_versions(&self, npm_package_id: Uuid) -> Result<Vec<NpmPackageVersion>, DomainError> {
        let rows = sqlx::query_as!(
            VersionRow,
            "SELECT id, npm_package_id, version, manifest, shasum, integrity, tarball_storage_key, tarball_size_bytes, \
                    deprecated, deprecated_message, published_by, published_at, origin \
             FROM npm_package_versions WHERE npm_package_id = $1 ORDER BY published_at",
            npm_package_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(VersionRow::into_domain).collect()
    }

    async fn list_versions_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<hangar_domain::npm_package::NpmPackageVersionSummary>, DomainError> {
        if npm_package_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as!(
            VersionSummaryRow,
            "SELECT npm_package_id, version, tarball_size_bytes, deprecated, published_at \
             FROM npm_package_versions WHERE npm_package_id = ANY($1) ORDER BY npm_package_id, published_at",
            npm_package_ids
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(VersionSummaryRow::into_domain).collect()
    }

    async fn find_version(&self, npm_package_id: Uuid, version: &NpmVersion) -> Result<Option<NpmPackageVersion>, DomainError> {
        let row = sqlx::query_as!(
            VersionRow,
            "SELECT id, npm_package_id, version, manifest, shasum, integrity, tarball_storage_key, tarball_size_bytes, \
                    deprecated, deprecated_message, published_by, published_at, origin \
             FROM npm_package_versions WHERE npm_package_id = $1 AND version = $2",
            npm_package_id,
            version.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(VersionRow::into_domain).transpose()
    }

    async fn insert_version(&self, version: &NpmPackageVersion) -> Result<(), DomainError> {
        let origin = match version.origin {
            NpmPackageOrigin::Local => "local",
            NpmPackageOrigin::ProxyCache => "proxy_cache",
        };
        // Transactional: a version row must never persist without its counter row.
        let mut tx = self.pool.begin().await.infra_err()?;
        sqlx::query!(
            "INSERT INTO npm_package_versions \
                (id, npm_package_id, version, manifest, shasum, integrity, tarball_storage_key, tarball_size_bytes, \
                 deprecated, deprecated_message, published_by, published_at, origin) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            version.id,
            version.npm_package_id,
            version.version.as_str(),
            version.manifest,
            version.shasum,
            version.integrity,
            version.tarball_storage_key,
            version.tarball_size_bytes,
            version.deprecated,
            version.deprecated_message,
            version.published_by,
            version.published_at,
            origin,
        )
        .execute(&mut *tx)
        .await
        .infra_err()?;
        sqlx::query!("INSERT INTO npm_download_counters (npm_package_version_id, count) VALUES ($1, 0)", version.id)
            .execute(&mut *tx)
            .await
            .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok(())
    }

    async fn delete_version(&self, npm_package_id: Uuid, version: &NpmVersion) -> Result<(), DomainError> {
        sqlx::query!(
            "DELETE FROM npm_package_versions WHERE npm_package_id = $1 AND version = $2",
            npm_package_id,
            version.as_str()
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn delete_package(&self, npm_package_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM npm_packages WHERE id = $1", npm_package_id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn set_deprecated(&self, npm_package_id: Uuid, version: &NpmVersion, message: Option<&str>) -> Result<(), DomainError> {
        sqlx::query!(
            "UPDATE npm_package_versions SET deprecated = TRUE, deprecated_message = $3 WHERE npm_package_id = $1 AND version = $2",
            npm_package_id,
            version.as_str(),
            message,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn list_dist_tags(&self, npm_package_id: Uuid) -> Result<Vec<NpmDistTag>, DomainError> {
        let rows = sqlx::query!("SELECT tag, version FROM npm_dist_tags WHERE npm_package_id = $1", npm_package_id)
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        rows.into_iter()
            .map(|r| Ok(NpmDistTag { npm_package_id, tag: r.tag, version: NpmVersion::parse(&r.version)? }))
            .collect()
    }

    async fn list_dist_tags_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<NpmDistTag>, DomainError> {
        if npm_package_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query!(
            "SELECT npm_package_id, tag, version FROM npm_dist_tags WHERE npm_package_id = ANY($1) ORDER BY npm_package_id",
            npm_package_ids
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter()
            .map(|r| Ok(NpmDistTag { npm_package_id: r.npm_package_id, tag: r.tag, version: NpmVersion::parse(&r.version)? }))
            .collect()
    }

    async fn set_dist_tag(&self, npm_package_id: Uuid, tag: &str, version: &NpmVersion) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO npm_dist_tags (npm_package_id, tag, version, updated_at) VALUES ($1, $2, $3, now()) \
             ON CONFLICT (npm_package_id, tag) DO UPDATE SET version = EXCLUDED.version, updated_at = now()",
            npm_package_id,
            tag,
            version.as_str(),
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn delete_dist_tag(&self, npm_package_id: Uuid, tag: &str) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM npm_dist_tags WHERE npm_package_id = $1 AND tag = $2", npm_package_id, tag)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn search(&self, repository_id: Uuid, query: &str, limit: i64) -> Result<Vec<NpmPackage>, DomainError> {
        let rows = sqlx::query_as!(
            SearchRow,
            "SELECT id, package_repository_id, name, created_at, updated_at \
             FROM npm_packages WHERE package_repository_id = $1 AND name ILIKE '%' || $2 || '%' ORDER BY name LIMIT $3",
            repository_id,
            query,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(SearchRow::into_domain).collect()
    }

    async fn increment_download_counter(&self, npm_package_version_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!(
            "UPDATE npm_download_counters SET count = count + 1, last_downloaded_at = now() WHERE npm_package_version_id = $1",
            npm_package_version_id
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn set_cached_metadata(&self, npm_package_id: Uuid, metadata: serde_json::Value) -> Result<(), DomainError> {
        sqlx::query!("UPDATE npm_packages SET cached_metadata = $2, updated_at = now() WHERE id = $1", npm_package_id, metadata)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

    fn sample_package(repository_id: Uuid, name: &str) -> NpmPackage {
        NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repository_id,
            name: NpmPackageName::parse(name).unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        }
    }

    #[sqlx::test]
    async fn creates_and_finds_a_package_by_name(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let found = repo.find_package(repository_id, &package.name).await.unwrap().unwrap();
        assert_eq!(found.id, package.id);
        assert_eq!(found.package_repository_id, repository_id);
        assert_eq!(found.name.as_str(), "left-pad");
        assert!(found.metadata_fetched_at.is_none());
        assert!(found.cached_metadata.is_none());

        let other_name = NpmPackageName::parse("right-pad").unwrap();
        assert!(repo.find_package(repository_id, &other_name).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn inserts_and_lists_versions(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let version = NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: NpmVersion::parse("1.0.0").unwrap(),
            manifest: serde_json::json!({"name": "left-pad"}), shasum: "abc".into(), integrity: "sha512-xyz".into(),
            tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(), tarball_size_bytes: 42,
            deprecated: false, deprecated_message: None, published_by: None, published_at: chrono::Utc::now(),
            origin: NpmPackageOrigin::Local,
        };
        repo.insert_version(&version).await.unwrap();

        let versions = repo.list_versions(package.id).await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].id, version.id);
        assert_eq!(versions[0].shasum, "abc");
        assert_eq!(versions[0].integrity, "sha512-xyz");
        assert_eq!(versions[0].tarball_storage_key, "left-pad/-/left-pad-1.0.0.tgz");
        assert_eq!(versions[0].tarball_size_bytes, 42);
        assert!(!versions[0].deprecated);
        assert_eq!(versions[0].origin, NpmPackageOrigin::Local);
        assert_eq!(versions[0].manifest, serde_json::json!({"name": "left-pad"}));

        let found = repo.find_version(package.id, &version.version).await.unwrap().unwrap();
        assert_eq!(found.id, version.id);

        let count: (i64,) =
            sqlx::query_as("SELECT count FROM npm_download_counters WHERE npm_package_version_id = $1")
                .bind(version.id)
                .fetch_one(&repo.pool)
                .await
                .unwrap();
        assert_eq!(count.0, 0);

        repo.delete_version(package.id, &version.version).await.unwrap();
        assert!(repo.list_versions(package.id).await.unwrap().is_empty());
        assert!(repo.find_version(package.id, &version.version).await.unwrap().is_none());
    }

    fn sample_version(npm_package_id: Uuid, version: &str) -> NpmPackageVersion {
        NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id, version: NpmVersion::parse(version).unwrap(),
            manifest: serde_json::json!({}), shasum: "abc".into(), integrity: "sha512-xyz".into(),
            tarball_storage_key: format!("pkg/-/pkg-{version}.tgz"), tarball_size_bytes: 1,
            deprecated: false, deprecated_message: None, published_by: None, published_at: chrono::Utc::now(),
            origin: NpmPackageOrigin::Local,
        }
    }

    #[sqlx::test]
    async fn list_versions_for_packages_batches_across_packages_without_cross_contamination(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let left_pad = sample_package(repository_id, "left-pad");
        let right_pad = sample_package(repository_id, "right-pad");
        repo.create_package(&left_pad).await.unwrap();
        repo.create_package(&right_pad).await.unwrap();
        repo.insert_version(&sample_version(left_pad.id, "1.0.0")).await.unwrap();
        repo.insert_version(&sample_version(left_pad.id, "2.0.0")).await.unwrap();
        repo.insert_version(&sample_version(right_pad.id, "1.0.0")).await.unwrap();

        let versions = repo.list_versions_for_packages(&[left_pad.id, right_pad.id]).await.unwrap();

        let left_pad_versions: Vec<_> = versions.iter().filter(|v| v.npm_package_id == left_pad.id).map(|v| v.version.as_str()).collect();
        let right_pad_versions: Vec<_> = versions.iter().filter(|v| v.npm_package_id == right_pad.id).map(|v| v.version.as_str()).collect();
        assert_eq!(versions.len(), 3);
        assert_eq!(left_pad_versions.len(), 2);
        assert_eq!(right_pad_versions, vec!["1.0.0"]);
    }

    #[sqlx::test]
    async fn list_versions_for_packages_is_empty_for_an_empty_input(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        assert!(repo.list_versions_for_packages(&[]).await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn dist_tags_round_trip(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();

        repo.set_dist_tag(package.id, "latest", &version).await.unwrap();
        let tags = repo.list_dist_tags(package.id).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].tag, "latest");
        assert_eq!(tags[0].version, version);
        assert_eq!(tags[0].npm_package_id, package.id);

        let version_2 = NpmVersion::parse("2.0.0").unwrap();
        repo.set_dist_tag(package.id, "latest", &version_2).await.unwrap();
        let tags = repo.list_dist_tags(package.id).await.unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].version, version_2);

        repo.delete_dist_tag(package.id, "latest").await.unwrap();
        assert!(repo.list_dist_tags(package.id).await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn search_matches_a_name_substring(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        repo.create_package(&sample_package(repository_id, "left-pad")).await.unwrap();
        repo.create_package(&sample_package(repository_id, "right-pad")).await.unwrap();

        let results = repo.search(repository_id, "left", 10).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name.as_str(), "left-pad");

        let all = repo.search(repository_id, "pad", 10).await.unwrap();
        assert_eq!(all.len(), 2);
        let limited = repo.search(repository_id, "pad", 1).await.unwrap();
        assert_eq!(limited.len(), 1);

        assert!(repo.search(repository_id, "nonexistent", 10).await.unwrap().is_empty());
    }

    #[sqlx::test]
    async fn touch_metadata_fetched_at_and_set_cached_metadata_update_the_package(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let fetched_at = chrono::Utc::now();
        repo.touch_metadata_fetched_at(package.id, fetched_at).await.unwrap();
        let found = repo.find_package(repository_id, &package.name).await.unwrap().unwrap();
        assert_eq!(
            found.metadata_fetched_at.unwrap().timestamp_millis(),
            fetched_at.timestamp_millis()
        );

        let metadata = serde_json::json!({"dist-tags": {"latest": "1.0.0"}});
        repo.set_cached_metadata(package.id, metadata.clone()).await.unwrap();
        let found = repo.find_package(repository_id, &package.name).await.unwrap().unwrap();
        assert_eq!(found.cached_metadata, Some(metadata));
    }

    #[sqlx::test]
    async fn set_deprecated_marks_the_version_deprecated_with_a_message(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let version = NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: NpmVersion::parse("1.0.0").unwrap(),
            manifest: serde_json::json!({"name": "left-pad"}), shasum: "abc".into(), integrity: "sha512-xyz".into(),
            tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(), tarball_size_bytes: 42,
            deprecated: false, deprecated_message: None, published_by: None, published_at: chrono::Utc::now(),
            origin: NpmPackageOrigin::Local,
        };
        repo.insert_version(&version).await.unwrap();

        repo.set_deprecated(package.id, &version.version, Some("use left-pad2 instead")).await.unwrap();
        let found = repo.find_version(package.id, &version.version).await.unwrap().unwrap();
        assert!(found.deprecated);
        assert_eq!(found.deprecated_message.as_deref(), Some("use left-pad2 instead"));
    }

    #[sqlx::test]
    async fn increment_download_counter_increases_count_and_sets_last_downloaded_at(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let version = NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: NpmVersion::parse("1.0.0").unwrap(),
            manifest: serde_json::json!({"name": "left-pad"}), shasum: "abc".into(), integrity: "sha512-xyz".into(),
            tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(), tarball_size_bytes: 42,
            deprecated: false, deprecated_message: None, published_by: None, published_at: chrono::Utc::now(),
            origin: NpmPackageOrigin::Local,
        };
        repo.insert_version(&version).await.unwrap();

        repo.increment_download_counter(version.id).await.unwrap();
        repo.increment_download_counter(version.id).await.unwrap();

        let row: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT count, last_downloaded_at FROM npm_download_counters WHERE npm_package_version_id = $1",
        )
        .bind(version.id)
        .fetch_one(&repo.pool)
        .await
        .unwrap();
        assert_eq!(row.0, 2);
        assert!(row.1.is_some());
    }

    #[sqlx::test]
    async fn delete_package_cascades_to_versions_and_dist_tags(pool: sqlx::PgPool) {
        let repo = PostgresNpmPackageRepository::new(pool);
        let repository_id = Uuid::new_v4();
        seed_repository(&repo.pool, repository_id).await;
        let package = sample_package(repository_id, "left-pad");
        repo.create_package(&package).await.unwrap();

        let version = NpmPackageVersion {
            id: Uuid::new_v4(), npm_package_id: package.id, version: NpmVersion::parse("1.0.0").unwrap(),
            manifest: serde_json::json!({"name": "left-pad"}), shasum: "abc".into(), integrity: "sha512-xyz".into(),
            tarball_storage_key: "left-pad/-/left-pad-1.0.0.tgz".into(), tarball_size_bytes: 42,
            deprecated: false, deprecated_message: None, published_by: None, published_at: chrono::Utc::now(),
            origin: NpmPackageOrigin::Local,
        };
        repo.insert_version(&version).await.unwrap();
        repo.set_dist_tag(package.id, "latest", &version.version).await.unwrap();

        repo.delete_package(package.id).await.unwrap();

        assert!(repo.find_package(repository_id, &package.name).await.unwrap().is_none());
        assert!(repo.list_versions(package.id).await.unwrap().is_empty());
        assert!(repo.list_dist_tags(package.id).await.unwrap().is_empty());
    }

    async fn seed_repository(pool: &sqlx::PgPool, id: Uuid) {
        sqlx::query!(
            "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, version, created_at, updated_at) \
             VALUES ($1, $2, $3, 'npm', 'hosted', NULL, 1, now(), now())",
            id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            format!("repo-{id}"),
        )
        .execute(pool)
        .await
        .unwrap();
    }
}
