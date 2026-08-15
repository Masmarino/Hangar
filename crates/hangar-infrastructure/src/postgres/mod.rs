
pub mod api_token_repository;
pub mod backup_code_repository;
pub mod branding_repository;
pub mod docker_image_scan_repository;
pub mod docker_manifest_repository;
pub mod docker_upload_session_repository;
pub mod metrics_snapshot_repository;
pub mod event_publisher;
pub mod health;
pub mod identity_provider_repository;
pub mod npm_dependency_audit_repository;
pub mod npm_package_repository;
pub mod organization_repository;
pub mod package_repository_store;
pub mod permission_store;
pub mod smtp_settings_repository;
pub mod system_settings_repository;
pub mod totp_credential_repository;
pub mod user_invitation_repository;
pub mod user_repository;
pub mod webauthn_credential_repository;

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub const DEFAULT_DB_MAX_CONNECTIONS: u32 = 10;

pub async fn connect(database_url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    // A short acquire timeout fails a request fast under pool exhaustion instead of hanging it.
    PgPoolOptions::new().max_connections(max_connections).acquire_timeout(Duration::from_secs(10)).connect(database_url).await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[cfg(test)]
mod tests {
    #[sqlx::test]
    async fn migrations_create_the_expected_tables(pool: sqlx::PgPool) {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let names: Vec<String> = rows.into_iter().map(|(n,)| n).collect();
        for expected in [
            "users",
            "domain_events",
            "permission_projections",
            "package_repository_projections",
            "package_repository_group_members",
        ] {
            assert!(names.contains(&expected.to_string()), "missing table {expected}");
        }
    }
}
