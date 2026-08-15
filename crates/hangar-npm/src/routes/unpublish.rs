use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::delete;
use axum::{Json, Router};
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};
use hangar_domain::permission::Role;
use serde::Deserialize;
use serde_json::json;

use crate::authz::{require_hosted, require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::auth::NpmAuthUser;
use crate::errors::{bad_request, npm_error_response};
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new()
        .route("/:repository/:package/-rev/:rev", delete(unpublish_package).put(unpublish_via_document_put))
        .route("/:repository/:package/-/:filename/-rev/:rev", delete(unpublish_version))
}

async fn unpublish_package(
    State(state): State<NpmState>,
    Path((repository, package, _rev)): Path<(String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "unpublish is not supported on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write)
        .await
        .map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;

    state.unpublish.execute_whole_package(repo.id, &name, user.id).await.map_err(npm_error_response)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct UnpublishDocument {
    #[serde(default)]
    versions: std::collections::HashMap<String, serde_json::Value>,
}

/// Real `npm unpublish` PUTs back the packument with the removed version's key gone, rather than calling a `DELETE` route — this diffs against the stored packument and unpublishes whatever disappeared. `rev` is never validated.
async fn unpublish_via_document_put(
    State(state): State<NpmState>,
    Path((repository, package, _rev)): Path<(String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
    Json(doc): Json<UnpublishDocument>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "unpublish is not supported on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write)
        .await
        .map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;

    let document = state
        .metadata
        .execute_hosted(repo.id, &name)
        .await
        .map_err(npm_error_response)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "package not found" }))))?;
    let current_versions: HashSet<String> = document
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let surviving_versions: HashSet<String> = doc.versions.keys().cloned().collect();

    for removed in current_versions.difference(&surviving_versions) {
        let Ok(version) = NpmVersion::parse(removed) else { continue };
        // Idempotent: a version already gone (e.g. cascade-deleted with the last surviving one) is not an error.
        match state.unpublish.execute_version(repo.id, &name, &version, user.id).await {
            Ok(()) => {}
            Err(hangar_application::error::ApplicationError::NpmPackageNotFound) => {}
            Err(hangar_application::error::ApplicationError::NpmVersionNotFound) => {}
            Err(e) => return Err(npm_error_response(e)),
        }
    }

    Ok(Json(json!({ "ok": true })))
}

async fn unpublish_version(
    State(state): State<NpmState>,
    Path((repository, package, filename, _rev)): Path<(String, String, String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "unpublish is not supported on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write)
        .await
        .map_err(|s| (s, Json(json!({ "error": "insufficient permissions" }))))?;
    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;
    let version = crate::routes::metadata::version_from_tarball_filename(&filename, &package)
        .ok_or_else(|| bad_request("could not derive a version from the tarball filename"))?;

    state.unpublish.execute_version(repo.id, &name, &version, user.id).await.map_err(npm_error_response)?;
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

    /// Mirrors `routes/metadata.rs`'s `test_state` — no shared test-support module for the HTTP-router `NpmState` builder.
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

    /// The returned `TempDir` guard must stay alive — dropping it deletes the tarballs.
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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn unpublishing_the_whole_package_deletes_it(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/widget/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.metadata.execute_hosted(repo_id, &name).await.unwrap().is_none(), "the whole package must be gone after a whole-package unpublish");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn unpublishing_a_single_existing_version_via_the_tarball_route_succeeds(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        state.publish.execute(repo_id, &name, &v2, json!({ "name": "widget", "version": "2.0.0" }), Bytes::from_static(b"v2-bytes"), user_id).await.unwrap();

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/widget/-/widget-1.0.0.tgz/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let document = state.metadata.execute_hosted(repo_id, &name).await.unwrap().unwrap();
        assert!(document["versions"]["1.0.0"].is_null(), "1.0.0 should have been removed");
        assert!(document["versions"]["2.0.0"].is_object(), "2.0.0 must be untouched");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn putting_back_a_packument_missing_one_version_removes_only_that_version(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        let v3 = NpmVersion::parse("3.0.0").unwrap();
        state.publish.execute(repo_id, &name, &v2, json!({ "name": "widget", "version": "2.0.0" }), Bytes::from_static(b"v2-bytes"), user_id).await.unwrap();
        state.publish.execute(repo_id, &name, &v3, json!({ "name": "widget", "version": "3.0.0" }), Bytes::from_static(b"v3-bytes"), user_id).await.unwrap();

        // Client posts back a packument with 2.0.0 missing — real npm's diff-based unpublish.
        let doc = json!({ "versions": { "1.0.0": {}, "3.0.0": {} } });

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let document = state.metadata.execute_hosted(repo_id, &name).await.unwrap().unwrap();
        assert!(document["versions"]["1.0.0"].is_object(), "1.0.0 was in the posted list, must survive");
        assert!(document["versions"]["2.0.0"].is_null(), "2.0.0 was missing from the posted list, must be removed");
        assert!(document["versions"]["3.0.0"].is_object(), "3.0.0 was in the posted list, must survive");
    }

    /// Posting back the exact same version list currently stored must be a true no-op.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn putting_back_the_same_version_list_removes_nothing(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        state.publish.execute(repo_id, &name, &v2, json!({ "name": "widget", "version": "2.0.0" }), Bytes::from_static(b"v2-bytes"), user_id).await.unwrap();

        let doc = json!({ "versions": { "1.0.0": {}, "2.0.0": {} } });

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let document = state.metadata.execute_hosted(repo_id, &name).await.unwrap().unwrap();
        assert!(document["versions"]["1.0.0"].is_object());
        assert!(document["versions"]["2.0.0"].is_object());
    }

    /// Needs a genuine race between two concurrent requests — a sequential one always recomputes the diff from the current packument, so it can never see a stale version.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_concurrent_duplicate_diff_request_is_tolerated_not_surfaced_as_an_error(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, user_id) = setup_with_one_published_version(&pool).await;
        let name = NpmPackageName::parse("widget").unwrap();
        let v2 = NpmVersion::parse("2.0.0").unwrap();
        state.publish.execute(repo_id, &name, &v2, json!({ "name": "widget", "version": "2.0.0" }), Bytes::from_static(b"v2-bytes"), user_id).await.unwrap();

        let doc = json!({ "versions": { "1.0.0": {} } });
        let app = crate::router(state.clone());

        let request = |rev: &str| {
            Request::builder()
                .method("PUT")
                .uri(format!("/{repo_name}/widget/-rev/{rev}"))
                .header("host", "acme.hangar.localhost")
                .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(doc.to_string()))
                .unwrap()
        };

        let (first, second) = tokio::join!(app.clone().oneshot(request("1")), app.oneshot(request("2")));
        let (first, second) = (first.unwrap(), second.unwrap());

        assert_eq!(first.status(), StatusCode::OK, "neither concurrent request may surface the race as an error");
        assert_eq!(second.status(), StatusCode::OK, "neither concurrent request may surface the race as an error");

        let document = state.metadata.execute_hosted(repo_id, &name).await.unwrap().unwrap();
        assert!(document["versions"]["1.0.0"].is_object(), "the surviving version must be untouched");
        assert!(document["versions"]["2.0.0"].is_null(), "2.0.0 must have been removed exactly once despite the race");
    }

    /// Unlike the diff-based route above, the plain per-version DELETE route isn't idempotent.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn unpublishing_a_nonexistent_version_via_the_delete_route_is_a_404_not_a_silent_success(pool: PgPool) {
        let (_dir, state, _repo_id, repo_name, _user_id) = setup_with_one_published_version(&pool).await;

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/widget/-/widget-9.9.9.tgz/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn unpublishing_against_a_proxy_repository_is_rejected(pool: PgPool) {
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
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/widget/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn unpublishing_by_a_caller_from_a_different_organization_is_rejected(pool: PgPool) {
        let (_dir, state, repo_id, repo_name, _acme_user_id) = setup_with_one_published_version(&pool).await;
        let other_id = Uuid::new_v4();
        create_org(&state, other_id, "other").await;
        let other_user_id = seed_user_with_active_token(&pool, other_id, "other-token").await;
        seed_permission(&pool, other_user_id, repo_id, "write").await;

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/widget/-rev/1"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer other-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "a write-role grant on a repository in a DIFFERENT organization must not let unpublish through the actual route");
    }
}
