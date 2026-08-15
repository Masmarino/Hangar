use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};
use hangar_domain::permission::Role;
use serde_json::json;

use crate::authz::{require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::auth::NpmAuthUser;
use crate::errors::{bad_request, npm_error_response};
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new()
        .route("/:repository/:package", get(get_metadata))
        .route("/:repository/:package/-/:filename", get(get_tarball))
}

async fn get_metadata(
    State(state): State<NpmState>,
    Path((repository, package)): Path<(String, String)>,
    headers: HeaderMap,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Read).await.map_err(|s| (s, Json(json!({ "error": "forbidden" }))))?;

    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;
    let document = state
        .metadata
        .execute(repo.id, &name)
        .await
        .map_err(npm_error_response)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "package not found" }))))?;

    let base = request_base_url(&headers, &repository);
    Ok(Json(rewrite_tarball_urls(document, &base, &package)))
}

async fn get_tarball(
    State(state): State<NpmState>,
    Path((repository, package, filename)): Path<(String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Read).await.map_err(|s| (s, Json(json!({ "error": "forbidden" }))))?;

    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;
    let version = version_from_tarball_filename(&filename, &package).ok_or_else(|| bad_request("invalid tarball filename"))?;

    let stream = state
        .download
        .execute_stream(repo.id, &name, &version)
        .await
        .map_err(npm_error_response)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "tarball not found" }))))?;

    // A published version's tarball never changes (npm rejects republishing), so a reverse proxy/CDN can serve repeat installs without hitting Hangar again.
    Ok((
        [("content-type", "application/octet-stream"), ("cache-control", "public, max-age=31536000, immutable")],
        Body::from_stream(stream),
    ))
}

/// Filenames are `{unscoped-name}-{version}.tgz`.
pub(crate) fn version_from_tarball_filename(filename: &str, package: &str) -> Option<NpmVersion> {
    let unscoped = unscoped_name(package);
    let stripped = filename.strip_prefix(unscoped)?.strip_prefix('-')?.strip_suffix(".tgz")?;
    NpmVersion::parse(stripped).ok()
}

fn unscoped_name(package: &str) -> &str {
    package.rsplit('/').next().unwrap_or(package)
}

fn request_base_url(headers: &HeaderMap, repository: &str) -> String {
    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("localhost");
    // Assumes http — a TLS-terminating reverse proxy would need X-Forwarded-Proto.
    format!("http://{host}/npm/{repository}")
}

fn rewrite_tarball_urls(mut document: serde_json::Value, base: &str, package: &str) -> serde_json::Value {
    let unscoped = unscoped_name(package);
    // `package` is already percent-decoded, so a scoped name has a literal `/` — re-encode it as `%2f` or the advertised tarball URL 404s.
    let encoded_package = package.replace('/', "%2f");
    if let Some(versions) = document.get_mut("versions").and_then(|v| v.as_object_mut()) {
        for (version, manifest) in versions.iter_mut() {
            if let Some(dist) = manifest.get_mut("dist").and_then(|d| d.as_object_mut()) {
                dist.insert(
                    "tarball".to_string(),
                    serde_json::Value::String(format!("{base}/{encoded_package}/-/{unscoped}-{version}.tgz")),
                );
            }
        }
    }
    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use bytes::Bytes;
    use hangar_application::use_cases::api_token::{CreateApiTokenUseCase, ListApiTokensUseCase, RevokeApiTokenUseCase, hash_api_token};
    use hangar_application::use_cases::npm_audit::BulkAuditNpmPackagesUseCase;
    use hangar_application::use_cases::npm_dependency_scan::ScanDependencyTreeUseCase;
    use hangar_application::use_cases::npm_deprecate::DeprecateNpmVersionUseCase;
    use hangar_application::use_cases::npm_dist_tags::{DeleteDistTagUseCase, ListDistTagsUseCase, SetDistTagUseCase};
    use hangar_application::use_cases::npm_download::DownloadNpmTarballUseCase;
    use hangar_application::use_cases::npm_publish::PublishNpmPackageUseCase;
    use hangar_application::use_cases::npm_search::SearchNpmPackagesUseCase;
    use hangar_application::use_cases::npm_unpublish::UnpublishNpmPackageUseCase;
    use hangar_domain::organization::{Organization, OrganizationSlug};
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
    use uuid::Uuid;

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
            metadata: Arc::new(hangar_application::use_cases::npm_metadata::GetNpmPackageMetadataUseCase::new(
                npm_packages.clone(),
                repositories.clone(),
                remote_registry.clone(),
            )),
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

    async fn seed_repository(pool: &PgPool, organization_id: Uuid, id: Uuid, format: &str, repo_type: &str) {
        sqlx::query!(
            "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, version, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, NULL, 1, now(), now())",
            id,
            organization_id,
            format!("repo-{id}"),
            format,
            repo_type,
        )
        .execute(pool)
        .await
        .unwrap();
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

    async fn seed_permission(pool: &PgPool, user_id: Uuid, repository_id: Uuid, role: &str) {
        sqlx::query!(
            "INSERT INTO permission_projections (user_id, repository_id, role, version, updated_at) VALUES ($1, $2, $3, 1, now())",
            user_id,
            repository_id,
            role,
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_repository_in_the_requested_organization_is_reachable_via_its_own_subdomain(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: acme_id,
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, acme_id, "acme-plaintext-token").await;
        seed_permission(&pool, user_id, repo_id, "read").await;

        let package_name = NpmPackageName::parse("acme-widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state
            .publish
            .execute(repo_id, &package_name, &version, json!({ "name": "acme-widget", "version": "1.0.0" }), Bytes::from_static(b"acme-tarball-bytes"), user_id)
            .await
            .unwrap();

        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/acme-widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-plaintext-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["name"], "acme-widget");
        assert!(document["versions"]["1.0.0"].is_object(), "the published version must appear in the returned metadata");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_package_in_one_organizations_repository_is_not_reachable_from_another_organization(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: acme_id,
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let other_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: other_id,
                slug: OrganizationSlug::parse("other").unwrap(),
                display_name: "Other".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
        seed_user_with_active_token(&pool, other_id, "plaintext-token").await;
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/repo-{repo_id}/some-package"))
                    .header("host", "other.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer plaintext-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Unlike the test above, this seeds an explicit grant and targets the repository's own OWNING organization — only a caller-organization check, not the lookup, can reject it.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_permission_grant_does_not_cross_an_organization_boundary(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: acme_id,
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let other_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: other_id,
                slug: OrganizationSlug::parse("other").unwrap(),
                display_name: "Other".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");

        // Publish a real package first, so the assertion below is explained by the org check, not a missing package.
        let acme_user_id = seed_user_with_active_token(&pool, acme_id, "acme-owns-this-package").await;
        seed_permission(&pool, acme_user_id, repo_id, "read").await;
        let package_name = NpmPackageName::parse("acme-widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state
            .publish
            .execute(repo_id, &package_name, &version, json!({ "name": "acme-widget", "version": "1.0.0" }), Bytes::from_static(b"cross-org-replay-tarball-bytes"), acme_user_id)
            .await
            .unwrap();

        // Belongs to "other", but holds a valid grant on acme's repository — a stale cross-org grant.
        let other_user_id = seed_user_with_active_token(&pool, other_id, "plaintext-token").await;
        seed_permission(&pool, other_user_id, repo_id, "read").await;
        let app = crate::router(state);

        // Sanity check: acme's own user can fetch the package it just published.
        let acme_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/acme-widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-owns-this-package")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(acme_get.status(), StatusCode::OK, "sanity check: the published package must be fetchable by its own organization");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/acme-widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer plaintext-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a valid role grant on a package that genuinely exists must not be enough to cross an organization boundary"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn downloading_a_tarball_carries_a_long_lived_cache_control_header(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
        state
            .organizations
            .create(&Organization {
                id: acme_id,
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, acme_id, "acme-plaintext-token").await;
        seed_permission(&pool, user_id, repo_id, "read").await;

        let package_name = NpmPackageName::parse("acme-widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state
            .publish
            .execute(repo_id, &package_name, &version, json!({ "name": "acme-widget", "version": "1.0.0" }), Bytes::from_static(b"acme-tarball-bytes"), user_id)
            .await
            .unwrap();

        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/acme-widget/-/acme-widget-1.0.0.tgz"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-plaintext-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable",
            "a published version's tarball never changes, so it must be safe to cache long-lived"
        );
    }
}
