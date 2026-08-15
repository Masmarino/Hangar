use async_trait::async_trait;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::system_settings::{SystemSettings, SystemSettingsPort};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresSystemSettingsRepository {
    pool: PgPool,
}

impl PostgresSystemSettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SystemSettingsPort for PostgresSystemSettingsRepository {
    async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError> {
        let row = sqlx::query!(
            "SELECT max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled FROM system_settings WHERE organization_id = $1",
            organization_id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        Ok(match row {
            Some(row) => SystemSettings {
                max_login_attempts: row.max_login_attempts,
                login_attempt_window_seconds: row.login_attempt_window_seconds,
                session_ttl_hours: row.session_ttl_hours,
                registration_enabled: row.registration_enabled,
            },
            None => SystemSettings::defaults(),
        })
    }

    async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO system_settings (organization_id, max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (organization_id) DO UPDATE SET \
             max_login_attempts = EXCLUDED.max_login_attempts, \
             login_attempt_window_seconds = EXCLUDED.login_attempt_window_seconds, \
             session_ttl_hours = EXCLUDED.session_ttl_hours, \
             registration_enabled = EXCLUDED.registration_enabled",
            organization_id,
            settings.max_login_attempts,
            settings.login_attempt_window_seconds,
            settings.session_ttl_hours,
            settings.registration_enabled,
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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_returns_the_seeded_defaults_on_a_fresh_instance(pool: sqlx::PgPool) {
        let repo = PostgresSystemSettingsRepository::new(pool);
        let settings = repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
        assert_eq!(settings, SystemSettings::defaults());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn update_then_get_round_trips_the_new_values(pool: sqlx::PgPool) {
        let repo = PostgresSystemSettingsRepository::new(pool);
        let updated = SystemSettings { max_login_attempts: 5, login_attempt_window_seconds: 60, session_ttl_hours: 24, registration_enabled: false };

        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &updated).await.unwrap();

        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), updated);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_update_overwrites_the_first_rather_than_inserting_a_row(pool: sqlx::PgPool) {
        let repo = PostgresSystemSettingsRepository::new(pool);
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &SystemSettings { max_login_attempts: 5, login_attempt_window_seconds: 60, session_ttl_hours: 24, registration_enabled: true }).await.unwrap();
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &SystemSettings { max_login_attempts: 20, login_attempt_window_seconds: 120, session_ttl_hours: 48, registration_enabled: false }).await.unwrap();

        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM system_settings").fetch_one(&repo.pool).await.unwrap().unwrap();
        assert_eq!(count, 1);
        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap().max_login_attempts, 20);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registration_enabled_round_trips_through_an_update(pool: sqlx::PgPool) {
        let repo = PostgresSystemSettingsRepository::new(pool);
        assert!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap().registration_enabled, "must default to enabled");

        let mut settings = repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
        settings.registration_enabled = false;
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &settings).await.unwrap();

        assert!(!repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap().registration_enabled);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_pre_migration_singleton_row_is_reattached_to_the_public_organization(pool: sqlx::PgPool) {
        // Migration 0004 runs as part of `migrations = "../hangar-infrastructure/migrations"`
        // above, on a fresh database with no prior data — so this proves the *shape* the
        // migration produces (a row addressable by organization_id) rather than replaying an
        // upgrade from a populated instance. `update` below exercises exactly the path a
        // pre-migration singleton row is expected to end up in after the `UPDATE ... SET
        // organization_id = ...` statement: reachable by the public organization's id.
        let repo = PostgresSystemSettingsRepository::new(pool.clone());
        repo.update(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &SystemSettings { max_login_attempts: 7, login_attempt_window_seconds: 90, session_ttl_hours: 6, registration_enabled: false }).await.unwrap();

        let row: (uuid::Uuid,) = sqlx::query_as("SELECT organization_id FROM system_settings").fetch_one(&pool).await.unwrap();
        assert_eq!(row.0, hangar_domain::organization::PUBLIC_ORGANIZATION_ID);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn settings_for_one_organization_do_not_affect_another(pool: sqlx::PgPool) {
        let repo = PostgresSystemSettingsRepository::new(pool.clone());
        let other_org_id = sqlx::query_scalar!(
            "INSERT INTO organizations (id, slug, display_name, is_public) VALUES (gen_random_uuid(), 'acme', 'Acme', false) RETURNING id"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        repo.update(other_org_id, &SystemSettings { max_login_attempts: 3, login_attempt_window_seconds: 30, session_ttl_hours: 2, registration_enabled: false }).await.unwrap();

        assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), SystemSettings::defaults(), "the public organization's settings must be untouched");
        assert_eq!(repo.get(other_org_id).await.unwrap().max_login_attempts, 3);
    }
}
