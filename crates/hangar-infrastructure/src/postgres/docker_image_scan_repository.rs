use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::docker_scan::{DockerImageScanRepositoryPort, DockerImageScanResult, DockerVulnerability};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresDockerImageScanRepository {
    pool: PgPool,
}

impl PostgresDockerImageScanRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct ScanRow {
    id: Uuid,
    docker_manifest_id: Uuid,
    scanned_at: DateTime<Utc>,
    vulnerabilities: serde_json::Value,
}

impl ScanRow {
    fn into_domain(self) -> Result<DockerImageScanResult, DomainError> {
        let vulnerabilities: Vec<DockerVulnerability> = serde_json::from_value(self.vulnerabilities)
            .map_err(|e| DomainError::Infrastructure(format!("deserializing docker image scan vulnerabilities: {e}")))?;
        Ok(DockerImageScanResult { id: self.id, docker_manifest_id: self.docker_manifest_id, scanned_at: self.scanned_at, vulnerabilities })
    }
}

#[async_trait]
impl DockerImageScanRepositoryPort for PostgresDockerImageScanRepository {
    async fn save(&self, result: &DockerImageScanResult) -> Result<(), DomainError> {
        let vulnerabilities = serde_json::to_value(&result.vulnerabilities)
            .map_err(|e| DomainError::Infrastructure(format!("serializing docker image scan vulnerabilities: {e}")))?;
        sqlx::query!(
            "INSERT INTO docker_image_scans (id, docker_manifest_id, scanned_at, vulnerabilities) VALUES ($1, $2, $3, $4)",
            result.id,
            result.docker_manifest_id,
            result.scanned_at,
            vulnerabilities,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn find_latest_for_manifest(&self, docker_manifest_id: Uuid) -> Result<Option<DockerImageScanResult>, DomainError> {
        let row = sqlx::query_as!(
            ScanRow,
            "SELECT id, docker_manifest_id, scanned_at, vulnerabilities \
             FROM docker_image_scans WHERE docker_manifest_id = $1 ORDER BY scanned_at DESC LIMIT 1",
            docker_manifest_id,
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(ScanRow::into_domain).transpose()
    }

    async fn find_latest_for_manifests(&self, docker_manifest_ids: &[Uuid]) -> Result<Vec<DockerImageScanResult>, DomainError> {
        if docker_manifest_ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as!(
            ScanRow,
            "SELECT DISTINCT ON (docker_manifest_id) id, docker_manifest_id, scanned_at, vulnerabilities \
             FROM docker_image_scans WHERE docker_manifest_id = ANY($1) \
             ORDER BY docker_manifest_id, scanned_at DESC",
            docker_manifest_ids,
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(ScanRow::into_domain).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_manifest(pool: &PgPool) -> Uuid {
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
        let manifest_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO docker_manifests (id, package_repository_id, image_name, digest, media_type, body, created_at) \
             VALUES ($1, $2, 'myimage', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', \
             'application/vnd.docker.distribution.manifest.v2+json', '{}', now())",
            manifest_id,
            repository_id,
        )
        .execute(pool)
        .await
        .unwrap();
        manifest_id
    }

    fn sample_result(docker_manifest_id: Uuid) -> DockerImageScanResult {
        DockerImageScanResult {
            id: Uuid::new_v4(),
            docker_manifest_id,
            scanned_at: Utc::now(),
            vulnerabilities: vec![DockerVulnerability {
                id: "CVE-2022-4450".to_string(),
                package_name: "libcrypto1.1".to_string(),
                installed_version: "1.1.1n-r0".to_string(),
                fixed_version: Some("1.1.1t-r0".to_string()),
                severity: "HIGH".to_string(),
                title: Some("openssl: double free after calling PEM_read_bio_ex".to_string()),
                primary_url: Some("https://avd.aquasec.com/nvd/cve-2022-4450".to_string()),
            }],
        }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn returns_none_when_never_scanned(pool: PgPool) {
        let repo = PostgresDockerImageScanRepository::new(pool.clone());
        let manifest_id = seed_manifest(&pool).await;

        assert!(repo.find_latest_for_manifest(manifest_id).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn saves_and_finds_the_latest_result(pool: PgPool) {
        let repo = PostgresDockerImageScanRepository::new(pool.clone());
        let manifest_id = seed_manifest(&pool).await;
        let result = sample_result(manifest_id);
        repo.save(&result).await.unwrap();

        let found = repo.find_latest_for_manifest(manifest_id).await.unwrap().unwrap();

        assert_eq!(found.id, result.id);
        assert_eq!(found.vulnerabilities.len(), 1);
        assert_eq!(found.vulnerabilities[0].id, "CVE-2022-4450");
        assert_eq!(found.vulnerabilities[0].severity, "HIGH");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_scan_becomes_the_latest_without_deleting_the_first(pool: PgPool) {
        let repo = PostgresDockerImageScanRepository::new(pool.clone());
        let manifest_id = seed_manifest(&pool).await;
        let first = sample_result(manifest_id);
        repo.save(&first).await.unwrap();

        let mut second = sample_result(manifest_id);
        second.id = Uuid::new_v4();
        second.vulnerabilities = vec![];
        repo.save(&second).await.unwrap();

        let found = repo.find_latest_for_manifest(manifest_id).await.unwrap().unwrap();
        assert_eq!(found.id, second.id);
        assert!(found.vulnerabilities.is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn find_latest_for_manifests_batches_across_several_manifests_and_skips_unscanned_ones(pool: PgPool) {
        let repo = PostgresDockerImageScanRepository::new(pool.clone());
        let scanned = seed_manifest(&pool).await;
        let never_scanned = seed_manifest(&pool).await;
        let first = sample_result(scanned);
        repo.save(&first).await.unwrap();
        let mut second = sample_result(scanned);
        second.id = Uuid::new_v4();
        second.vulnerabilities = vec![];
        repo.save(&second).await.unwrap();

        let mut found = repo.find_latest_for_manifests(&[scanned, never_scanned]).await.unwrap();

        assert_eq!(found.len(), 1, "the never-scanned manifest must simply be absent, not a zero-value entry");
        let found = found.remove(0);
        assert_eq!(found.id, second.id, "must be the most recent scan, not the first one saved");
        assert!(found.vulnerabilities.is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn find_latest_for_manifests_is_empty_for_an_empty_input(pool: PgPool) {
        let repo = PostgresDockerImageScanRepository::new(pool);
        assert!(repo.find_latest_for_manifests(&[]).await.unwrap().is_empty());
    }
}
