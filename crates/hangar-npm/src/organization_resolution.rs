use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use hangar_domain::organization::{Organization, OrganizationSlug};

use crate::state::NpmState;

/// Copy of `hangar_api::organization_middleware::ResolvedOrganization`, adapted to this crate's own `NpmState` — can't share across the crate boundary.
#[derive(Clone)]
pub struct ResolvedOrganization(pub Organization);

#[async_trait]
impl FromRequestParts<NpmState> for ResolvedOrganization {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &NpmState) -> Result<Self, Self::Rejection> {
        let host = parts
            .headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Strip a port if present, and lowercase — an uppercase Host header must resolve
        // the same as its lowercase form.
        let host_without_port = host.split(':').next().unwrap_or(host).to_ascii_lowercase();

        let label = host_without_port
            .strip_suffix(&format!(".{}", state.hangar_base_domain))
            .unwrap_or("");

        let org = if label.is_empty() || label == "www" {
            state
                .organizations
                .find_public()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        } else {
            let slug = OrganizationSlug::parse(label).map_err(|_| StatusCode::NOT_FOUND)?;
            state
                .organizations
                .find_by_slug(&slug)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?
        };

        Ok(ResolvedOrganization(org))
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

    fn router(state: NpmState) -> Router {
        async fn handler(ResolvedOrganization(org): ResolvedOrganization) -> String {
            org.slug.as_str().to_string()
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    async fn create_org(state: &NpmState, slug: &str) {
        state
            .organizations
            .create(&Organization {
                id: uuid::Uuid::new_v4(),
                slug: OrganizationSlug::parse(slug).unwrap(),
                display_name: slug.to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }

    async fn resolve(state: NpmState, host: &str) -> axum::response::Response {
        router(state)
            .oneshot(Request::builder().uri("/").header("host", host).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_plain_base_domain_host_resolves_to_the_public_organization(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let response = resolve(state, "hangar.localhost").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "public".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_www_host_label_resolves_to_the_public_organization(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let response = resolve(state, "www.hangar.localhost").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "public".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_slug_dot_base_domain_host_resolves_to_that_organization(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        create_org(&state, "acme").await;
        let response = resolve(state, "acme.hangar.localhost").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "acme".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_port_suffix_on_the_host_header_is_stripped(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let response = resolve(state, "hangar.localhost:8080").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "public".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_port_suffix_on_an_organization_subdomain_is_stripped(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        create_org(&state, "acme").await;
        let response = resolve(state, "acme.hangar.localhost:8080").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "acme".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_uppercase_host_header_still_resolves_the_organization(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        create_org(&state, "acme").await;
        let response = resolve(state, "ACME.HANGAR.LOCALHOST").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "acme".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_unknown_organization_slug_is_not_found(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let response = resolve(state, "nope.hangar.localhost").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Guards against a substring match instead of an exact dot-boundary label match —
    /// `evilacme` contains `acme` but is a distinct slug, so this must 404.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_host_that_merely_contains_another_organizations_slug_is_not_confused_with_it(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        create_org(&state, "acme").await;
        let response = resolve(state, "evilacme.hangar.localhost").await;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a host whose label merely contains another organization's slug must not resolve to that organization"
        );
    }

    /// Guards against matching the base domain's first occurrence instead of anchoring to
    /// the end of the host — a spoofed `acme.hangar.localhost.evil.com` must fall back to
    /// public, not resolve to acme.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_host_where_the_base_domain_appears_as_a_substring_but_not_as_the_final_label_does_not_match(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        create_org(&state, "acme").await;
        let response = resolve(state, "acme.hangar.localhost.evil.com").await;
        assert_eq!(response.status(), StatusCode::OK, "must not error, but also must not be treated as acme");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body, "public".as_bytes(),
            "the base domain appearing mid-host (not as the final label) must fall back to public, never match \"acme\""
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_host_that_does_not_end_with_the_base_domain_falls_back_to_the_public_organization(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let response = resolve(state, "totally-unrelated-host.example.com").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "public".as_bytes());
    }
}
