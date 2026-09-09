use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};
use hangar_domain::permission::Role;
use serde_json::json;

use crate::authz::{require_hosted, require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::auth::NpmAuthUser;
use crate::errors::{bad_request, npm_error_response};
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new()
        .route("/{repository}/-/package/{package}/dist-tags", get(list_tags))
        .route("/{repository}/-/package/{package}/dist-tags/{tag}", put(set_tag).delete(delete_tag))
}

async fn list_tags(
    State(state): State<NpmState>,
    Path((repository, package)): Path<(String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Read).await.map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;

    let tags = state.list_dist_tags.execute(repo.id, &name).await.map_err(npm_error_response)?;
    let map: HashMap<String, String> = tags.into_iter().map(|t| (t.tag, t.version.as_str())).collect();
    Ok(Json(map))
}

async fn set_tag(
    State(state): State<NpmState>,
    Path((repository, package, tag)): Path<(String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
    body: String,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "dist-tags cannot be set on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write).await.map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;
    // npm sends the version as a raw JSON string, e.g. "1.0.0" — no full JSON parse needed.
    let version_str = body.trim().trim_matches('"');
    let version = NpmVersion::parse(version_str).map_err(|_| bad_request("invalid version"))?;

    state.set_dist_tag.execute(repo.id, &name, &tag, &version, user.id).await.map_err(npm_error_response)?;
    Ok(Json(json!({ "ok": true })))
}

async fn delete_tag(
    State(state): State<NpmState>,
    Path((repository, package, tag)): Path<(String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "dist-tags cannot be deleted on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write).await.map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;

    state.delete_dist_tag.execute(repo.id, &name, &tag).await.map_err(npm_error_response)?;
    Ok(Json(json!({ "ok": true })))
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
    use hangar_application::use_cases::npm_metadata::GetNpmPackageMetadataUseCase;
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

    /// Mirrors `routes/metadata.rs`'s `test_state` — this crate has no shared
    /// test-support module for the HTTP-router `NpmState` builder.
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

    async fn create_org(state: &NpmState, id: Uuid, slug: &str) {
        state
            .organizations
            .create(&Organization { id, slug: OrganizationSlug::parse(slug).unwrap(), display_name: slug.to_string(), is_public: false, created_at: chrono::Utc::now() })
            .await
            .unwrap();
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

    /// npm-hosted repository, a user with write+read access, and one published version
    /// (1.0.0, which the publish use case's own `latest`-on-first-publish behavior already
    /// tags). Returns (TempDir guard — MUST be kept alive, state, repo_id, repo_name, user_id).
    async fn setup_with_one_published_version(pool: &PgPool) -> (tempfile::TempDir, NpmState, Uuid, String, Uuid) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(pool, org_id, "acme-token").await;
        seed_permission(pool, user_id, repo_id, "write").await;

        let name = NpmPackageName::parse("widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state.publish.execute(repo_id, &name, &version, json!({ "name": "widget", "version": "1.0.0" }), Bytes::from_static(b"tarball-bytes"), user_id).await.unwrap();

        (dir, state, repo_id, repo_name, user_id)
    }

    fn put_dist_tag(app: axum::Router, repo_name: &str, tag: &str, raw_body: &str, bearer: &str) -> impl std::future::Future<Output = axum::response::Response> {
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/{repo_name}/-/package/widget/dist-tags/{tag}"))
            .header("host", "acme.hangar.localhost")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::from(raw_body.to_string()))
            .unwrap();
        async move { app.oneshot(request).await.unwrap() }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_to_a_valid_version_succeeds(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();

        let app = crate::router(state.clone());
        // Real npm clients send the version as a bare (unquoted-in-transit) string body...
        let response = put_dist_tag(app, &repo_name, "beta", "1.0.0", "acme-token").await;

        assert_eq!(response.status(), StatusCode::OK);
        let tags = state.list_dist_tags.execute(repo_id, &name).await.unwrap();
        assert!(tags.iter().any(|t| t.tag == "beta" && t.version.as_str() == "1.0.0"));
    }

    /// The hand-rolled `body.trim().trim_matches('"')` parsing this file uses instead of a
    /// full JSON parse — npm's actual HTTP client sends the version JSON-string-quoted
    /// (`"1.0.0"`), not bare, so this is the realistic wire format, not the edge case.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_with_a_json_quoted_version_is_correctly_unquoted(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();

        let app = crate::router(state.clone());
        let response = put_dist_tag(app, &repo_name, "beta", "\"1.0.0\"", "acme-token").await;

        assert_eq!(response.status(), StatusCode::OK);
        let tags = state.list_dist_tags.execute(repo_id, &name).await.unwrap();
        assert!(
            tags.iter().any(|t| t.tag == "beta" && t.version.as_str() == "1.0.0"),
            "a JSON-string-quoted version must be unquoted before parsing, found: {tags:?}"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_with_surrounding_whitespace_is_trimmed(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();

        let app = crate::router(state.clone());
        let response = put_dist_tag(app, &repo_name, "beta", "  \"1.0.0\"  \n", "acme-token").await;

        assert_eq!(response.status(), StatusCode::OK);
        let tags = state.list_dist_tags.execute(repo_id, &name).await.unwrap();
        assert!(tags.iter().any(|t| t.tag == "beta" && t.version.as_str() == "1.0.0"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn listing_dist_tags_returns_previously_set_tags(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state.set_dist_tag.execute(repo_id, &name, "beta", &version, user_id).await.unwrap();

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/-/package/widget/dist-tags"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let map: HashMap<String, String> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(map.get("latest").map(String::as_str), Some("1.0.0"), "publish's own latest-tag-on-first-publish must be visible");
        assert_eq!(map.get("beta").map(String::as_str), Some("1.0.0"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_a_dist_tag_removes_it(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state.set_dist_tag.execute(repo_id, &name, "beta", &version, user_id).await.unwrap();

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/-/package/widget/dist-tags/beta"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let tags = state.list_dist_tags.execute(repo_id, &name).await.unwrap();
        assert!(!tags.iter().any(|t| t.tag == "beta"), "the deleted tag must no longer be listed");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_to_a_nonexistent_version_is_rejected_not_silently_accepted(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();

        let app = crate::router(state.clone());
        let response = put_dist_tag(app, &repo_name, "latest", "\"9.9.9\"", "acme-token").await;

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "setting a dist-tag to a version that was never published must be rejected, not silently accepted"
        );
        let tags = state.list_dist_tags.execute(repo_id, &name).await.unwrap();
        assert!(
            !tags.iter().any(|t| t.tag == "latest" && t.version.as_str() == "9.9.9"),
            "`latest` must not have been moved to a nonexistent version"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_against_a_proxy_repository_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "proxy").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let app = crate::router(state);
        let response = put_dist_tag(app, &repo_name, "beta", "1.0.0", "acme-token").await;

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "dist-tags cannot be set on a proxy repository, must be rejected at the route level");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn setting_a_dist_tag_by_a_caller_from_a_different_organization_is_rejected(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _acme_user_id) = setup_with_one_published_version(&pool).await;
        let other_id = Uuid::new_v4();
        create_org(&state, other_id, "other").await;
        let other_user_id = seed_user_with_active_token(&pool, other_id, "other-token").await;
        seed_permission(&pool, other_user_id, repo_id, "write").await;

        let app = crate::router(state);
        let response = put_dist_tag(app, &repo_name, "beta", "1.0.0", "other-token").await;

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a write-role grant on a repository in a DIFFERENT organization must not let a dist-tag change through the actual route"
        );
    }
}
