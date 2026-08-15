use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::organization::{Organization, OrganizationRepositoryPort, OrganizationSlug};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error_ext::InfraErr;

pub struct PostgresOrganizationRepository {
    pool: PgPool,
}

impl PostgresOrganizationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct OrganizationRow {
    id: Uuid,
    slug: String,
    display_name: String,
    is_public: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl OrganizationRow {
    fn into_domain(self) -> Result<Organization, DomainError> {
        Ok(Organization {
            id: self.id,
            slug: OrganizationSlug::parse(&self.slug)?,
            display_name: self.display_name,
            is_public: self.is_public,
            created_at: self.created_at,
        })
    }
}

#[async_trait]
impl OrganizationRepositoryPort for PostgresOrganizationRepository {
    async fn create(&self, org: &Organization) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO organizations (id, slug, display_name, is_public, created_at) VALUES ($1, $2, $3, $4, $5)",
            org.id,
            org.slug.as_str(),
            org.display_name,
            org.is_public,
            org.created_at,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        row.map(OrganizationRow::into_domain).transpose()
    }

    async fn find_by_slug(&self, slug: &OrganizationSlug) -> Result<Option<Organization>, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE slug = $1", slug.as_str())
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        row.map(OrganizationRow::into_domain).transpose()
    }

    async fn find_public(&self) -> Result<Organization, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE is_public")
            .fetch_one(&self.pool)
            .await
            .infra_err()?;
        row.into_domain()
    }

    async fn list_all(&self) -> Result<Vec<Organization>, DomainError> {
        let rows = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        rows.into_iter().map(OrganizationRow::into_domain).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[sqlx::test]
    async fn the_seeded_public_organization_is_found(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let public = repo.find_public().await.unwrap();
        assert_eq!(public.slug.as_str(), "public");
        assert!(public.is_public);
    }

    #[sqlx::test]
    async fn creating_then_finding_by_slug_round_trips(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let org = Organization {
            id: Uuid::new_v4(),
            slug: OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme Corp".to_string(),
            is_public: false,
            created_at: Utc::now(),
        };
        repo.create(&org).await.unwrap();

        let found = repo.find_by_slug(&OrganizationSlug::parse("acme").unwrap()).await.unwrap().unwrap();
        assert_eq!(found.id, org.id);
        assert_eq!(found.display_name, "Acme Corp");
    }

    #[sqlx::test]
    async fn finding_by_an_unknown_slug_returns_none(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        assert!(repo.find_by_slug(&OrganizationSlug::parse("nope").unwrap()).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn list_all_includes_the_seeded_public_organization_and_created_ones(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let org = Organization {
            id: Uuid::new_v4(),
            slug: OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme Corp".to_string(),
            is_public: false,
            created_at: Utc::now(),
        };
        repo.create(&org).await.unwrap();

        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|o| o.is_public));
        assert!(all.iter().any(|o| o.id == org.id));
    }
}
