use std::sync::Arc;

use hangar_domain::organization::{Organization, OrganizationRepositoryPort, OrganizationSlug};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct CreateOrganizationUseCase {
    organizations: Arc<dyn OrganizationRepositoryPort>,
}

impl CreateOrganizationUseCase {
    pub fn new(organizations: Arc<dyn OrganizationRepositoryPort>) -> Self {
        Self { organizations }
    }

    pub async fn execute(&self, slug: &str, display_name: &str) -> Result<Uuid, ApplicationError> {
        let slug = OrganizationSlug::parse(slug)?;
        if self.organizations.find_by_slug(&slug).await?.is_some() {
            return Err(ApplicationError::OrganizationSlugTaken);
        }
        let id = Uuid::new_v4();
        let org = Organization { id, slug, display_name: display_name.to_string(), is_public: false, created_at: chrono::Utc::now() };
        self.organizations.create(&org).await?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_an_organization_succeeds_and_is_findable(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations.clone());

        let id = use_case.execute("acme", "Acme Corp").await.unwrap();

        let found = organizations.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(found.slug.as_str(), "acme");
        assert_eq!(found.display_name, "Acme Corp");
        assert!(!found.is_public);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_an_organization_with_a_taken_slug_fails(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations.clone());
        use_case.execute("acme", "Acme Corp").await.unwrap();

        let result = use_case.execute("acme", "Acme Corp Again").await;

        assert!(matches!(result, Err(ApplicationError::OrganizationSlugTaken)));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_invalid_slug_is_rejected_before_touching_the_database(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations);

        let result = use_case.execute("1nvalid", "Whatever").await;

        assert!(result.is_err());
    }
}
