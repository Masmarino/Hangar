use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::put;
use axum::{Json, Router};
use base64::Engine;
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};
use hangar_domain::permission::Role;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::authz::{require_hosted, require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::auth::NpmAuthUser;
use crate::errors::{bad_request, npm_error_response};
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new().route("/:repository/:package", put(publish))
}

#[derive(Deserialize)]
struct PublishDocument {
    #[serde(default)]
    versions: HashMap<String, serde_json::Value>,
    #[serde(rename = "_attachments", default)]
    attachments: HashMap<String, Attachment>,
}

#[derive(Deserialize)]
struct Attachment {
    data: String,
}

async fn publish(
    State(state): State<NpmState>,
    Path((repository, package)): Path<(String, String)>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
    Json(doc): Json<PublishDocument>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_hosted(&repo).map_err(|s| (s, Json(json!({ "error": "publish is not supported on a proxy or group repository" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Write)
        .await
        .map_err(|s| (s, Json(json!({ "error": "insufficient permissions to publish" }))))?;

    let name = NpmPackageName::parse(&package).map_err(|_| bad_request("invalid package name"))?;

    if doc.attachments.is_empty() {
        // No tarball attached — a metadata-only update (`npm deprecate`), not a new publish.
        for (version_str, manifest) in &doc.versions {
            let Ok(version) = NpmVersion::parse(version_str) else { continue };
            let message = manifest.get("deprecated").and_then(|d| d.as_str());
            if message.is_some() {
                state
                    .deprecate
                    .execute(repo.id, &name, &version, message, user.id)
                    .await
                    .map_err(npm_error_response)?;
            }
        }
        return Ok((StatusCode::OK, Json(json!({ "ok": true, "id": name.as_str(), "rev": Uuid::new_v4().to_string() }))));
    }

    let attachment = doc.attachments.values().next().ok_or_else(|| bad_request("publish document has no tarball attachment"))?;
    let tarball_bytes = base64::engine::general_purpose::STANDARD
        .decode(&attachment.data)
        .map_err(|_| bad_request("invalid base64 tarball data"))?;

    // A plain `npm publish` document carries exactly one new version.
    let (version_str, manifest) = doc.versions.into_iter().next().ok_or_else(|| bad_request("publish document has no versions"))?;
    let version = NpmVersion::parse(&version_str).map_err(|_| bad_request("invalid version string"))?;

    state.publish.execute(repo.id, &name, &version, manifest, bytes::Bytes::from(tarball_bytes), user.id).await.map_err(npm_error_response)?;

    // Fire-and-forget: must not hold up the publish response. Errors are swallowed — the manual rescan button is the recovery path.
    let scan = state.scan_dependency_tree.clone();
    let scan_repo_id = repo.id;
    let scan_name = name.clone();
    let scan_version = version.clone();
    tokio::spawn(async move {
        let _ = scan.execute(scan_repo_id, &scan_name, &scan_version).await;
    });

    Ok((StatusCode::CREATED, Json(json!({ "ok": true, "id": name.as_str(), "rev": Uuid::new_v4().to_string() }))))
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

    async fn seed_organization_admin_with_active_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
        let user_id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at) VALUES ($1, $2, 'irrelevant', false, true, $3, now())",
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

    fn publish_body(version: &str, attachment_name: Option<&str>, tarball_base64: Option<&str>, extra_manifest_fields: serde_json::Value) -> serde_json::Value {
        let mut manifest = json!({ "name": "widget", "version": version });
        if let (serde_json::Value::Object(base), serde_json::Value::Object(extra)) = (&mut manifest, &extra_manifest_fields) {
            for (k, v) in extra {
                base.insert(k.clone(), v.clone());
            }
        }
        let mut doc = json!({ "versions": { version: manifest } });
        if let (Some(name), Some(data)) = (attachment_name, tarball_base64) {
            doc["_attachments"] = json!({ name: { "data": data } });
        }
        doc
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_publish_with_a_tarball_succeeds(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("1.0.0", Some("widget-1.0.0.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED, "a genuine new-version publish with a tarball must be treated as a real publish (201), not a metadata-only update");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["id"], "widget");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_publish_document_with_no_attachments_only_deprecates_and_does_not_create_a_version(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let name = NpmPackageName::parse("widget").unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state.publish.execute(repo_id, &name, &version, json!({ "name": "widget", "version": "1.0.0" }), Bytes::from_static(b"real-tarball"), user_id).await.unwrap();

        // Real `npm deprecate` PUTs the packument back with a `deprecated` message and NO `_attachments` key.
        let doc = json!({ "versions": { "1.0.0": { "name": "widget", "version": "1.0.0", "deprecated": "use widget2 instead" } } });

        let app = crate::router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "a no-attachment publish document is a metadata-only update (deprecate), must be 200 not 201");

        let document = state.metadata.execute_hosted(repo_id, &name).await.unwrap().unwrap();
        assert_eq!(
            document["versions"]["1.0.0"]["deprecated"], "use widget2 instead",
            "the existing version must have been deprecated in place, not replaced"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_with_an_invalid_package_name_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("1.0.0", Some("Bad-1.0.0.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        // Uppercase letters are not a valid npm package name segment.
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/Bad-Name"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_with_an_invalid_version_string_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("not-a-version", Some("widget-x.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_with_invalid_base64_tarball_data_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let body = publish_body("1.0.0", Some("widget-1.0.0.tgz"), Some("not-valid-base64!!!"), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// Proves `require_hosted` is actually wired up at this route, not just unit-tested in `authz.rs`.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_against_a_proxy_repository_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "proxy").await;
        let repo_name = format!("repo-{repo_id}");
        let user_id = seed_user_with_active_token(&pool, org_id, "acme-token").await;
        seed_permission(&pool, user_id, repo_id, "write").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("1.0.0", Some("widget-1.0.0.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer acme-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "publish must be rejected on a proxy repository at the route level, not just in the unit-tested require_hosted() itself");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_by_a_caller_from_a_different_organization_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let other_id = Uuid::new_v4();
        create_org(&state, other_id, "other").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        // A caller from a different organization holding an explicit (stale) grant on acme's repository.
        let other_user_id = seed_user_with_active_token(&pool, other_id, "other-token").await;
        seed_permission(&pool, other_user_id, repo_id, "write").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("1.0.0", Some("widget-1.0.0.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer other-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a valid write-role grant on a repository in a DIFFERENT organization must not let a publish through the actual route"
        );
    }

    /// Mirrors hangar-api's org-admin bypass (`hangar_api::authz::effective_repository_role`) — implicit Write on any repository in their own org, no explicit grant needed.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn publishing_as_an_organization_admin_of_the_repositorys_own_organization_succeeds_without_an_explicit_grant(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let org_id = Uuid::new_v4();
        create_org(&state, org_id, "acme").await;
        let repo_id = Uuid::new_v4();
        seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        // Deliberately no `seed_permission` call — the org-admin bypass must not need one.
        seed_organization_admin_with_active_token(&pool, org_id, "org-admin-token").await;

        let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(b"tarball-bytes");
        let body = publish_body("1.0.0", Some("widget-1.0.0.tgz"), Some(&tarball_b64), json!({}));

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/widget"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, "Bearer org-admin-token")
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }
}
