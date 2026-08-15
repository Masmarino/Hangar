use async_trait::async_trait;
use axum::RequestPartsExt;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use chrono::Utc;
use hangar_application::use_cases::api_token::hash_api_token;
use uuid::Uuid;

use crate::state::NpmState;

#[derive(Clone)]
pub struct NpmAuthUser {
    pub id: Uuid,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
}

#[async_trait]
impl FromRequestParts<NpmState> for NpmAuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &NpmState) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            parts.extract::<TypedHeader<Authorization<Bearer>>>().await.map_err(|_| StatusCode::UNAUTHORIZED)?;
        let hash = hash_api_token(bearer.token());
        let token = state
            .api_tokens
            .find_by_hash(&hash)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if !token.is_active() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let _ = state.api_tokens.touch_last_used_at(token.id, Utc::now()).await;
        let user = state
            .users
            .find_by_id(token.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(NpmAuthUser { id: user.id, is_super_admin: user.is_super_admin, is_organization_admin: user.is_organization_admin, organization_id: user.organization_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use hangar_application::use_cases::api_token::{CreateApiTokenUseCase, ListApiTokensUseCase, RevokeApiTokenUseCase};
    use hangar_application::use_cases::npm_audit::BulkAuditNpmPackagesUseCase;
    use hangar_application::use_cases::npm_dependency_scan::ScanDependencyTreeUseCase;
    use hangar_application::use_cases::npm_deprecate::DeprecateNpmVersionUseCase;
    use hangar_application::use_cases::npm_dist_tags::{DeleteDistTagUseCase, ListDistTagsUseCase, SetDistTagUseCase};
    use hangar_application::use_cases::npm_download::DownloadNpmTarballUseCase;
    use hangar_application::use_cases::npm_metadata::GetNpmPackageMetadataUseCase;
    use hangar_application::use_cases::npm_publish::PublishNpmPackageUseCase;
    use hangar_application::use_cases::npm_search::SearchNpmPackagesUseCase;
    use hangar_application::use_cases::npm_unpublish::UnpublishNpmPackageUseCase;
    use hangar_infrastructure::filesystem_storage::FilesystemStorageBackend;
    use hangar_infrastructure::http_npm_audit_client::HttpNpmAuditClient;
    use hangar_infrastructure::http_remote_npm_registry::HttpRemoteNpmRegistry;
    use hangar_infrastructure::postgres::api_token_repository::PostgresApiTokenRepository;
    use hangar_infrastructure::postgres::npm_dependency_audit_repository::PostgresDependencyAuditRepository;
    use hangar_infrastructure::postgres::npm_package_repository::PostgresNpmPackageRepository;
    use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;
    use hangar_infrastructure::postgres::package_repository_store::PostgresPackageRepositoryStore;
    use hangar_infrastructure::postgres::permission_store::PostgresPermissionStore;
    use hangar_infrastructure::postgres::user_repository::PostgresUserRepository;
    use hangar_infrastructure::postgres::event_publisher::PostgresEventPublisher;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Mirrors the `NpmState` builder duplicated in `routes/metadata.rs`,
    /// `authz.rs` and `organization_resolution.rs` — this crate has no shared
    /// test-support module (see `routes/metadata.rs`'s own note on this).
    async fn test_state(pool: PgPool, root: &std::path::Path) -> NpmState {
        let users = Arc::new(PostgresUserRepository::new(pool.clone()));
        let repositories = Arc::new(PostgresPackageRepositoryStore::new(pool.clone(), "test-secret".to_string()));
        let permissions = Arc::new(PostgresPermissionStore::new(pool.clone()));
        let api_tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort> = Arc::new(PostgresApiTokenRepository::new(pool.clone()));
        let organizations: Arc<dyn hangar_domain::organization::OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
        let npm_packages: Arc<dyn hangar_domain::npm_package::NpmPackageRepositoryPort> = Arc::new(PostgresNpmPackageRepository::new(pool.clone()));
        let npm_audit: Arc<dyn hangar_domain::npm_audit::NpmAuditPort> = Arc::new(HttpNpmAuditClient::new());
        let dependency_audits: Arc<dyn hangar_domain::npm_audit::DependencyAuditRepositoryPort> = Arc::new(PostgresDependencyAuditRepository::new(pool.clone()));
        let storage: Arc<dyn hangar_domain::storage::StorageBackendPort> = Arc::new(FilesystemStorageBackend::new(root.to_path_buf()));
        let events: Arc<dyn hangar_domain::audit::EventPublisherPort> = Arc::new(PostgresEventPublisher::new(pool.clone()));
        let remote_registry: Arc<dyn hangar_domain::npm_remote::RemoteNpmRegistryPort> = Arc::new(HttpRemoteNpmRegistry::new());

        NpmState {
            users: users.clone(),
            repositories: repositories.clone(),
            permissions: permissions.clone(),
            api_tokens: api_tokens.clone(),
            organizations: organizations.clone(),
            hangar_base_domain: "hangar.localhost".to_string(),
            publish: Arc::new(PublishNpmPackageUseCase::new(npm_packages.clone(), storage.clone(), repositories.clone(), events.clone())),
            metadata: Arc::new(GetNpmPackageMetadataUseCase::new(npm_packages.clone(), repositories.clone(), remote_registry.clone())),
            download: Arc::new(DownloadNpmTarballUseCase::new(npm_packages.clone(), storage.clone(), remote_registry.clone(), repositories.clone())),
            unpublish: Arc::new(UnpublishNpmPackageUseCase::new(npm_packages.clone(), storage.clone(), events.clone())),
            deprecate: Arc::new(DeprecateNpmVersionUseCase::new(npm_packages.clone(), events.clone())),
            set_dist_tag: Arc::new(SetDistTagUseCase::new(npm_packages.clone(), events.clone())),
            delete_dist_tag: Arc::new(DeleteDistTagUseCase::new(npm_packages.clone())),
            list_dist_tags: Arc::new(ListDistTagsUseCase::new(npm_packages.clone())),
            search: Arc::new(SearchNpmPackagesUseCase::new(npm_packages.clone())),
            bulk_audit: Arc::new(BulkAuditNpmPackagesUseCase::new(npm_audit.clone())),
            scan_dependency_tree: Arc::new(ScanDependencyTreeUseCase::new(npm_packages.clone(), remote_registry.clone(), npm_audit.clone(), dependency_audits.clone())),
            create_api_token: Arc::new(CreateApiTokenUseCase::new(api_tokens.clone())),
            list_api_tokens: Arc::new(ListApiTokensUseCase::new(api_tokens.clone())),
            revoke_api_token: Arc::new(RevokeApiTokenUseCase::new(api_tokens.clone())),
        }
    }

    async fn seed_organization(pool: &PgPool) -> Uuid {
        let org_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO organizations (id, slug, display_name, is_public, created_at) VALUES ($1, $2, $3, false, now())",
            org_id,
            format!("org-{}", &org_id.simple().to_string()[..8]),
            "Test Org",
        )
        .execute(pool)
        .await
        .unwrap();
        org_id
    }

    async fn seed_user_with_active_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
        let user_id = Uuid::new_v4();
        // Usernames cap at 32 chars, so truncate the UUID rather than use it whole.
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_super_admin, organization_id, created_at) VALUES ($1, $2, 'irrelevant', false, $3, now())",
            user_id,
            format!("user-{}", &user_id.simple().to_string()[..8]),
            organization_id,
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO api_tokens (id, user_id, token_hash, label, created_at) VALUES ($1, $2, $3, 'test', now())",
            Uuid::new_v4(),
            user_id,
            hash_api_token(plaintext_token),
        )
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    async fn seed_user_with_revoked_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_super_admin, organization_id, created_at) VALUES ($1, $2, 'irrelevant', false, $3, now())",
            user_id,
            format!("user-{}", &user_id.simple().to_string()[..8]),
            organization_id,
        )
        .execute(pool)
        .await
        .unwrap();
        // A previously-issued, now-revoked token — must behave exactly like one that never
        // existed, not merely like an unauthenticated request.
        sqlx::query!(
            "INSERT INTO api_tokens (id, user_id, token_hash, label, created_at, revoked_at) VALUES ($1, $2, $3, 'test', now(), now())",
            Uuid::new_v4(),
            user_id,
            hash_api_token(plaintext_token),
        )
        .execute(pool)
        .await
        .unwrap();
        user_id
    }

    fn router(state: NpmState) -> Router {
        async fn handler(user: NpmAuthUser) -> String {
            user.id.to_string()
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    async fn request(state: NpmState, auth_header: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().uri("/");
        if let Some(value) = auth_header {
            builder = builder.header(axum::http::header::AUTHORIZATION, value);
        }
        router(state).oneshot(builder.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_active_token_authenticates_successfully(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = seed_organization(&pool).await;
        let user_id = seed_user_with_active_token(&pool, org_id, "valid-plaintext-token").await;

        let response = request(state, Some("Bearer valid-plaintext-token")).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, user_id.to_string().as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_missing_authorization_header_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        let response = request(state, None).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_malformed_authorization_header_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        // Wrong auth scheme entirely — `TypedHeader<Authorization<Bearer>>` extraction fails.
        let response = request(state, Some("Basic dXNlcjpwYXNz")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_unknown_token_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        // No token with this hash exists in the database at all.
        let response = request(state, Some("Bearer this-token-was-never-issued")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_revoked_token_is_rejected_not_silently_accepted(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = seed_organization(&pool).await;
        seed_user_with_revoked_token(&pool, org_id, "revoked-plaintext-token").await;

        let response = request(state, Some("Bearer revoked-plaintext-token")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a revoked token must not authenticate");
    }
}
