use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::npm_audit::{DependencyAuditFinding, DependencyAuditRepositoryPort, DependencyAuditResult};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresDependencyAuditRepository {
    pool: PgPool,
}

impl PostgresDependencyAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct AuditRow {
    id: Uuid,
    npm_package_version_id: Uuid,
    scanned_at: DateTime<Utc>,
    packages_scanned: i32,
    truncated: bool,
    findings: serde_json::Value,
}

impl AuditRow {
    fn into_domain(self) -> Result<DependencyAuditResult, DomainError> {
        let findings: Vec<DependencyAuditFinding> = serde_json::from_value(self.findings)
            .map_err(|e| DomainError::Infrastructure(format!("deserializing dependency audit findings: {e}")))?;
        Ok(DependencyAuditResult {
            id: self.id,
            npm_package_version_id: self.npm_package_version_id,
            scanned_at: self.scanned_at,
            packages_scanned: self.packages_scanned,
            truncated: self.truncated,
            findings,
        })
    }
}

#[async_trait]
impl DependencyAuditRepositoryPort for PostgresDependencyAuditRepository {
    async fn save(&self, result: &DependencyAuditResult) -> Result<(), DomainError> {
        let findings = serde_json::to_value(&result.findings)
            .map_err(|e| DomainError::Infrastructure(format!("serializing dependency audit findings: {e}")))?;
        sqlx::query!(
            "INSERT INTO npm_dependency_audits (id, npm_package_version_id, scanned_at, packages_scanned, truncated, findings) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            result.id,
            result.npm_package_version_id,
            result.scanned_at,
            result.packages_scanned,
            result.truncated,
            findings,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn find_latest_for_version(&self, npm_package_version_id: Uuid) -> Result<Option<DependencyAuditResult>, DomainError> {
        let row = sqlx::query_as!(
            AuditRow,
            "SELECT id, npm_package_version_id, scanned_at, packages_scanned, truncated, findings \
             FROM npm_dependency_audits WHERE npm_package_version_id = $1 ORDER BY scanned_at DESC LIMIT 1",
            npm_package_version_id,
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(AuditRow::into_domain).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hangar_domain::npm_audit::NpmAdvisory;

    async fn seed_version(pool: &PgPool) -> Uuid {
        let repository_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, version, created_at, updated_at) \
             VALUES ($1, $2, $3, 'npm', 'hosted', 1, now(), now())",
            repository_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            format!("repo-{repository_id}"),
        )
        .execute(pool)
        .await
        .unwrap();
        let package_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO npm_packages (id, package_repository_id, name) VALUES ($1, $2, 'left-pad')",
            package_id,
            repository_id,
        )
        .execute(pool)
        .await
        .unwrap();
        let version_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO npm_package_versions (id, npm_package_id, version, manifest, shasum, integrity, tarball_storage_key, tarball_size_bytes, origin) \
             VALUES ($1, $2, '1.0.0', '{}', 's', 'i', 'k', 1, 'local')",
            version_id,
            package_id,
        )
        .execute(pool)
        .await
        .unwrap();
        version_id
    }

    fn sample_result(npm_package_version_id: Uuid) -> DependencyAuditResult {
        DependencyAuditResult {
            id: Uuid::new_v4(),
            npm_package_version_id,
            scanned_at: Utc::now(),
            packages_scanned: 12,
            truncated: false,
            findings: vec![DependencyAuditFinding {
                dependency_name: "minimist".to_string(),
                dependency_version: "0.0.8".to_string(),
                advisory: NpmAdvisory {
                    id: 1097677,
                    url: "https://github.com/advisories/GHSA-xvch-5gv4-984h".to_string(),
                    title: "Prototype Pollution in minimist".to_string(),
                    severity: "critical".to_string(),
                    vulnerable_versions: "<0.2.4".to_string(),
                    cwe: vec!["CWE-1321".to_string()],
                    cvss_score: Some(9.8),
                },
            }],
        }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn returns_none_when_never_scanned(pool: PgPool) {
        let repo = PostgresDependencyAuditRepository::new(pool.clone());
        let version_id = seed_version(&pool).await;

        assert!(repo.find_latest_for_version(version_id).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn saves_and_finds_the_latest_result(pool: PgPool) {
        let repo = PostgresDependencyAuditRepository::new(pool.clone());
        let version_id = seed_version(&pool).await;
        let result = sample_result(version_id);
        repo.save(&result).await.unwrap();

        let found = repo.find_latest_for_version(version_id).await.unwrap().unwrap();

        assert_eq!(found.id, result.id);
        assert_eq!(found.packages_scanned, 12);
        assert!(!found.truncated);
        assert_eq!(found.findings.len(), 1);
        assert_eq!(found.findings[0].dependency_name, "minimist");
        assert_eq!(found.findings[0].advisory.severity, "critical");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_scan_becomes_the_latest_without_deleting_the_first(pool: PgPool) {
        let repo = PostgresDependencyAuditRepository::new(pool.clone());
        let version_id = seed_version(&pool).await;
        let first = sample_result(version_id);
        repo.save(&first).await.unwrap();

        let mut second = sample_result(version_id);
        second.id = Uuid::new_v4();
        second.packages_scanned = 20;
        second.findings = vec![];
        repo.save(&second).await.unwrap();

        let found = repo.find_latest_for_version(version_id).await.unwrap().unwrap();
        assert_eq!(found.id, second.id);
        assert_eq!(found.packages_scanned, 20);
        assert!(found.findings.is_empty());
    }
}
