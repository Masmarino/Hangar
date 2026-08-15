use async_trait::async_trait;
use hangar_domain::email::{SmtpSecurity, SmtpSettings, SmtpSettingsPort};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sqlx::PgPool;
use uuid::Uuid;

use crate::secret_box;

pub struct PostgresSmtpSettingsRepository {
    pool: PgPool,
    /// Derives the AES-256 key for `secret_box` — never stored, never logged.
    secrets_encryption_key: String,
}

impl PostgresSmtpSettingsRepository {
    pub fn new(pool: PgPool, secrets_encryption_key: String) -> Self {
        Self { pool, secrets_encryption_key }
    }
}

fn security_to_str(security: SmtpSecurity) -> &'static str {
    match security {
        SmtpSecurity::None => "none",
        SmtpSecurity::StartTls => "starttls",
        SmtpSecurity::Tls => "tls",
    }
}

fn security_from_str(raw: &str) -> Option<SmtpSecurity> {
    match raw {
        "none" => Some(SmtpSecurity::None),
        "starttls" => Some(SmtpSecurity::StartTls),
        "tls" => Some(SmtpSecurity::Tls),
        _ => None,
    }
}

#[async_trait]
impl SmtpSettingsPort for PostgresSmtpSettingsRepository {
    async fn get(&self, organization_id: Uuid) -> Result<Option<SmtpSettings>, DomainError> {
        let row = sqlx::query!(
            "SELECT host, port, username, encrypted_password, password_nonce, from_name, from_address, security FROM smtp_settings WHERE organization_id = $1",
            organization_id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let password = secret_box::decrypt(&row.encrypted_password, &row.password_nonce, &self.secrets_encryption_key)?;
        let security = security_from_str(&row.security).ok_or_else(|| DomainError::Infrastructure(format!("unknown smtp security {}", row.security)))?;
        Ok(Some(SmtpSettings { host: row.host, port: row.port, username: row.username, password, from_name: row.from_name, from_address: row.from_address, security }))
    }

    async fn update(&self, organization_id: Uuid, settings: &SmtpSettings) -> Result<(), DomainError> {
        let (encrypted_password, password_nonce) = secret_box::encrypt(&settings.password, &self.secrets_encryption_key);
        sqlx::query!(
            "INSERT INTO smtp_settings (organization_id, host, port, username, encrypted_password, password_nonce, from_name, from_address, security) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (organization_id) DO UPDATE SET \
             host = EXCLUDED.host, port = EXCLUDED.port, username = EXCLUDED.username, \
             encrypted_password = EXCLUDED.encrypted_password, password_nonce = EXCLUDED.password_nonce, \
             from_name = EXCLUDED.from_name, from_address = EXCLUDED.from_address, security = EXCLUDED.security",
            organization_id,
            settings.host,
            settings.port,
            settings.username,
            encrypted_password,
            password_nonce,
            settings.from_name,
            settings.from_address,
            security_to_str(settings.security),
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

    fn sample() -> SmtpSettings {
        SmtpSettings {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "hangar@example.com".to_string(),
            password: "s3cret!".to_string(),
            from_name: "Hangar".to_string(),
            from_address: "hangar@example.com".to_string(),
            security: SmtpSecurity::StartTls,
        }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_returns_none_when_never_configured(pool: sqlx::PgPool) {
        let repo = PostgresSmtpSettingsRepository::new(pool, "jwt-secret".to_string());
        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn update_then_get_round_trips_including_the_password(pool: sqlx::PgPool) {
        let repo = PostgresSmtpSettingsRepository::new(pool, "jwt-secret".to_string());
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &sample()).await.unwrap();

        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), Some(sample()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_update_overwrites_the_first_rather_than_inserting_a_row(pool: sqlx::PgPool) {
        let repo = PostgresSmtpSettingsRepository::new(pool, "jwt-secret".to_string());
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &sample()).await.unwrap();
        let updated = SmtpSettings { host: "smtp2.example.com".to_string(), ..sample() };
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &updated).await.unwrap();

        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM smtp_settings").fetch_one(&repo.pool).await.unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap().unwrap().host, "smtp2.example.com");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_password_is_never_stored_in_plaintext(pool: sqlx::PgPool) {
        let repo = PostgresSmtpSettingsRepository::new(pool, "jwt-secret".to_string());
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &sample()).await.unwrap();

        let row: (Vec<u8>,) = sqlx::query_as("SELECT encrypted_password FROM smtp_settings WHERE organization_id = $1").bind(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).fetch_one(&repo.pool).await.unwrap();
        let stored = String::from_utf8_lossy(&row.0);
        assert!(!stored.contains("s3cret!"), "the plaintext password must never appear in the stored bytes");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn settings_for_one_organization_do_not_affect_another(pool: sqlx::PgPool) {
        let repo = PostgresSmtpSettingsRepository::new(pool.clone(), "test-secret".to_string());
        let other_org_id = sqlx::query_scalar!(
            "INSERT INTO organizations (id, slug, display_name, is_public) VALUES (gen_random_uuid(), 'acme', 'Acme', false) RETURNING id"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        repo.update(other_org_id, &sample()).await.unwrap();

        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), None, "the public organization must still be unconfigured");
        assert!(repo.get(other_org_id).await.unwrap().is_some());
    }
}
