use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::auth::DockerAuthUser;
use crate::errors::docker_error_response;
use crate::organization_resolution::ResolvedOrganization;
use crate::state::DockerState;

pub fn router() -> Router<DockerState> {
    Router::new().route("/_catalog", get(list_catalog))
}

async fn list_catalog(State(state): State<DockerState>, resolved_org: ResolvedOrganization, user: DockerAuthUser) -> Response {
    match state.list_registry_catalog.execute(resolved_org.0.id, user.user_id).await {
        Ok(names) => Json(json!({ "repositories": names })).into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hangar_domain::docker_registry::Digest;
    use hangar_domain::organization::PUBLIC_ORGANIZATION_ID;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::route_test_support::{issue_test_token, seed_permission, seed_repository, test_state};

    async fn push_config_blob(app: &axum::Router, repo_name: &str, push_token: &str, config_bytes: &[u8]) -> Digest {
        let digest = Digest::of(config_bytes);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(config_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        digest
    }

    async fn push_manifest(app: &axum::Router, repo_name: &str, push_token: &str, image_name: &str, config_bytes: &[u8]) {
        let config_digest = push_config_blob(app, repo_name, push_token, config_bytes).await;
        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/{image_name}/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "schemaVersion": 2,
                            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                            "config": { "digest": config_digest.as_str() },
                            "layers": []
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn catalog_lists_only_repositories_the_caller_can_read(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let readable_id = Uuid::new_v4();
        let unreadable_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, readable_id, "docker", "hosted").await;
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, unreadable_id, "docker", "hosted").await;
        let readable_name = format!("repo-{readable_id}");
        let unreadable_name = format!("repo-{unreadable_id}");
        let state = test_state(pool.clone(), dir.path()).await;
        let user_id = Uuid::new_v4();
        seed_permission(&pool, user_id, readable_id, "read").await;
        let push_token = issue_test_token(&state, user_id, readable_id, &readable_name, "myimage", &["push"]);
        let app = crate::router(state.clone());
        push_manifest(&app, &readable_name, &push_token, "myimage", b"catalog-config-bytes").await;

        let other_user_id = Uuid::new_v4();
        let admin_push_token = issue_test_token(&state, other_user_id, unreadable_id, &unreadable_name, "secretimage", &["push"]);
        push_manifest(&app, &unreadable_name, &admin_push_token, "secretimage", b"unreadable-config-bytes").await;

        let catalog_token = state.token_issuer.issue(user_id, PUBLIC_ORGANIZATION_ID, false, None).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_catalog")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {catalog_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repositories = json["repositories"].as_array().unwrap();
        assert_eq!(repositories, &vec![serde_json::json!(format!("{readable_name}/myimage"))]);
        assert!(!repositories.iter().any(|r| r.as_str().unwrap().starts_with(&unreadable_name)));
    }

    /// Repository names are only unique per-organization (Task 7) — without organization
    /// scoping, `_catalog` would leak another organization's repository existence and could
    /// even collide two different organizations' same-named repositories into one entry.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn catalog_only_lists_the_resolved_organizations_own_repositories(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let acme_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let state = test_state(pool.clone(), dir.path()).await;
        state
            .organizations
            .create(&hangar_domain::organization::Organization {
                id: acme_id,
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        state
            .organizations
            .create(&hangar_domain::organization::Organization {
                id: other_id,
                slug: hangar_domain::organization::OrganizationSlug::parse("other").unwrap(),
                display_name: "Other".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let acme_repo_id = Uuid::new_v4();
        seed_repository(&pool, acme_id, acme_repo_id, "docker", "hosted").await;
        let acme_repo_name = format!("repo-{acme_repo_id}");
        let acme_user_id = Uuid::new_v4();
        seed_permission(&pool, acme_user_id, acme_repo_id, "read").await;
        let acme_push_token = crate::route_test_support::issue_test_token_for_org(&state, acme_user_id, acme_id, false, acme_repo_id, &acme_repo_name, "myimage", &["push"]);
        let app = crate::router(state.clone());

        // Inlined rather than the shared push helpers, which assume the public organization
        // — this repository lives in "acme".
        let config_bytes: &[u8] = b"acme-config-bytes";
        let config_digest = hangar_domain::docker_registry::Digest::of(config_bytes);
        let blob_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{acme_repo_name}/myimage/blobs/uploads/?digest={}", config_digest.as_str()))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {acme_push_token}"))
                    .body(Body::from(config_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blob_response.status(), StatusCode::CREATED);
        let manifest_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{acme_repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {acme_push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "schemaVersion": 2,
                            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                            "config": { "digest": config_digest.as_str() },
                            "layers": []
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(manifest_response.status(), StatusCode::CREATED);

        // Same super-admin scope query, but hitting the OTHER organization's own subdomain —
        // must not see "acme"'s repository at all, regardless of read permissions.
        let other_user_id = Uuid::new_v4();
        seed_permission(&pool, other_user_id, acme_repo_id, "read").await;
        let catalog_token = state.token_issuer.issue(other_user_id, other_id, false, None).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_catalog")
                    .header("host", "other.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {catalog_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repositories = json["repositories"].as_array().unwrap();
        assert!(repositories.is_empty(), "must not list a repository from a different organization: {repositories:?}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn catalog_requires_authentication(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::router(test_state(pool, dir.path()).await);

        let response = app.oneshot(Request::builder().uri("/_catalog").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
