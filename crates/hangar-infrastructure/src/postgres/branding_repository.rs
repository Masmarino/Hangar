use async_trait::async_trait;
use hangar_domain::branding::{BrandingAsset, BrandingPort, BrandingSettings};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresBrandingRepository {
    pool: PgPool,
}

impl PostgresBrandingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BrandingPort for PostgresBrandingRepository {
    async fn get(&self, organization_id: Uuid) -> Result<BrandingSettings, DomainError> {
        let row = sqlx::query!(
            "SELECT logo_bytes, logo_content_type, favicon_bytes, favicon_content_type FROM branding_settings WHERE organization_id = $1",
            organization_id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        let Some(row) = row else {
            return Ok(BrandingSettings::default());
        };
        let logo = match (row.logo_bytes, row.logo_content_type) {
            (Some(bytes), Some(content_type)) => Some(BrandingAsset { bytes, content_type }),
            _ => None,
        };
        let favicon = match (row.favicon_bytes, row.favicon_content_type) {
            (Some(bytes), Some(content_type)) => Some(BrandingAsset { bytes, content_type }),
            _ => None,
        };
        Ok(BrandingSettings { logo, favicon })
    }

    async fn set_logo(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO branding_settings (organization_id, logo_bytes, logo_content_type) VALUES ($1, $2, $3) \
             ON CONFLICT (organization_id) DO UPDATE SET logo_bytes = EXCLUDED.logo_bytes, logo_content_type = EXCLUDED.logo_content_type",
            organization_id,
            asset.bytes,
            asset.content_type,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn clear_logo(&self, organization_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO branding_settings (organization_id, logo_bytes, logo_content_type) VALUES ($1, NULL, NULL) \
             ON CONFLICT (organization_id) DO UPDATE SET logo_bytes = NULL, logo_content_type = NULL",
            organization_id
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn set_favicon(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO branding_settings (organization_id, favicon_bytes, favicon_content_type) VALUES ($1, $2, $3) \
             ON CONFLICT (organization_id) DO UPDATE SET favicon_bytes = EXCLUDED.favicon_bytes, favicon_content_type = EXCLUDED.favicon_content_type",
            organization_id,
            asset.bytes,
            asset.content_type,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn clear_favicon(&self, organization_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO branding_settings (organization_id, favicon_bytes, favicon_content_type) VALUES ($1, NULL, NULL) \
             ON CONFLICT (organization_id) DO UPDATE SET favicon_bytes = NULL, favicon_content_type = NULL",
            organization_id
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org_id() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    fn sample_logo() -> BrandingAsset {
        BrandingAsset { bytes: vec![1, 2, 3, 4], content_type: "image/png".to_string() }
    }

    fn sample_favicon() -> BrandingAsset {
        BrandingAsset { bytes: vec![5, 6, 7], content_type: "image/x-icon".to_string() }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_returns_defaults_when_never_configured(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        assert_eq!(repo.get(org_id()).await.unwrap(), BrandingSettings::default());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn set_logo_then_get_round_trips(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();

        let settings = repo.get(org_id()).await.unwrap();
        assert_eq!(settings.logo, Some(sample_logo()));
        assert_eq!(settings.favicon, None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_logo_and_favicon_independently_does_not_clobber_the_other(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();
        repo.set_favicon(org_id(), &sample_favicon()).await.unwrap();

        let settings = repo.get(org_id()).await.unwrap();
        assert_eq!(settings.logo, Some(sample_logo()));
        assert_eq!(settings.favicon, Some(sample_favicon()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clear_logo_resets_to_none_without_touching_favicon(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();
        repo.set_favicon(org_id(), &sample_favicon()).await.unwrap();

        repo.clear_logo(org_id()).await.unwrap();

        let settings = repo.get(org_id()).await.unwrap();
        assert_eq!(settings.logo, None);
        assert_eq!(settings.favicon, Some(sample_favicon()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_set_logo_overwrites_the_first_rather_than_inserting_a_row(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();
        let replacement = BrandingAsset { bytes: vec![9, 9, 9], content_type: "image/jpeg".to_string() };
        repo.set_logo(org_id(), &replacement).await.unwrap();

        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM branding_settings").fetch_one(&repo.pool).await.unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(repo.get(org_id()).await.unwrap().logo, Some(replacement));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clear_favicon_resets_to_none_without_touching_logo(pool: sqlx::PgPool) {
        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();
        repo.set_favicon(org_id(), &sample_favicon()).await.unwrap();

        repo.clear_favicon(org_id()).await.unwrap();

        let settings = repo.get(org_id()).await.unwrap();
        assert_eq!(settings.logo, Some(sample_logo()));
        assert_eq!(settings.favicon, None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn branding_is_isolated_per_organization(pool: sqlx::PgPool) {
        let other_org_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO organizations (id, slug, display_name, is_public) VALUES ($1, 'other', 'Other', false)",
            other_org_id
        )
        .execute(&pool)
        .await
        .unwrap();

        let repo = PostgresBrandingRepository::new(pool);
        repo.set_logo(org_id(), &sample_logo()).await.unwrap();
        repo.set_logo(other_org_id, &sample_favicon()).await.unwrap();

        assert_eq!(repo.get(org_id()).await.unwrap().logo, Some(sample_logo()));
        assert_eq!(repo.get(other_org_id).await.unwrap().logo, Some(sample_favicon()));
    }
}
