use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hangar_domain::docker_registry::DockerImageName;
use serde_json::json;
use uuid::Uuid;

use crate::auth::DockerAuthUser;
use crate::authz::{require_docker_repository, require_granted_action, require_repository_by_name};
use crate::errors::{docker_error, docker_error_response};
use crate::state::DockerState;

pub async fn list_tags(state: DockerState, organization_id: Uuid, repository_name: String, image_name_str: String, user: DockerAuthUser) -> Response {
    let repo = match require_repository_by_name(&state, &user, organization_id, &repository_name).await {
        Ok(repo) => repo,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = require_docker_repository(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_granted_action(&user, repo.id, &repository_name, "pull") {
        return status.into_response();
    }
    let Ok(image_name) = DockerImageName::parse(&image_name_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "invalid image name").into_response();
    };

    match state.list_tags.execute(repo.id, &image_name).await {
        Ok(tags) => Json(json!({ "name": image_name_str, "tags": tags })).into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hangar_domain::docker_registry::Digest;
    use hangar_domain::organization::PUBLIC_ORGANIZATION_ID;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::route_test_support::{issue_test_token, seed_repository, test_state};

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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lists_tags_for_a_pushed_image(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        let repo_name = format!("repo-{repository_id}");
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let config_digest = push_config_blob(&app, &repo_name, &push_token, b"tags-list-config-bytes").await;
        let manifest_body = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": { "digest": config_digest.as_str() },
            "layers": []
        }))
        .unwrap();

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/v1"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(manifest_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/tags/list"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["tags"], serde_json::json!(["v1"]));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn listing_tags_with_a_token_scoped_to_a_different_repository_is_forbidden(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        let repo_name = format!("repo-{repository_id}");
        let state = test_state(pool, dir.path()).await;
        let token = issue_test_token(&state, Uuid::new_v4(), Uuid::new_v4(), "some-other-repo", "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/tags/list"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
