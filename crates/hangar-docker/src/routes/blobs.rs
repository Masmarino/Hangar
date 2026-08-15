use axum::body::{Body, Bytes};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hangar_domain::docker_registry::{Digest, DockerImageName};
use uuid::Uuid;

use crate::auth::DockerAuthUser;
use crate::authz::{require_docker_repository, require_granted_action, require_hosted, require_repository_by_name};
use crate::errors::{docker_error, docker_error_response};
use crate::state::DockerState;

/// Parses the `start` out of a `Content-Range: <start>-<end>` header value.
fn parse_content_range_start(header: &str) -> Option<i64> {
    header.split('-').next()?.trim().parse().ok()
}

pub async fn start_or_monolithic_upload(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name: String,
    digest_query: Option<String>,
    user: DockerAuthUser,
    body: Bytes,
) -> Response {
    let repo = match require_repository_by_name(&state, &user, organization_id, &repository_name).await {
        Ok(repo) => repo,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = require_docker_repository(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_hosted(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_granted_action(&user, repo.id, &repository_name, "push") {
        return status.into_response();
    }

    if let Some(digest_str) = digest_query {
        let Ok(digest) = Digest::parse(&digest_str) else {
            return docker_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "invalid digest").into_response();
        };
        return match state.monolithic_upload.execute(repo.id, &digest, body.to_vec()).await {
            Ok(()) => (
                StatusCode::CREATED,
                [(header::LOCATION, format!("/v2/{repository_name}/{image_name}/blobs/{}", digest.as_str()))],
            )
                .into_response(),
            Err(e) => docker_error_response(e).into_response(),
        };
    }

    match state.start_upload.execute(repo.id).await {
        Ok(session) => (
            StatusCode::ACCEPTED,
            [
                (header::LOCATION, format!("/v2/{repository_name}/{image_name}/blobs/uploads/{}", session.id)),
                (HeaderName::from_static("range"), "0-0".to_string()),
                (HeaderName::from_static("docker-upload-uuid"), session.id.to_string()),
            ],
        )
            .into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

pub async fn patch_chunk(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name: String,
    upload_id: String,
    content_range: Option<String>,
    user: DockerAuthUser,
    chunk: Bytes,
) -> Response {
    let repo = match require_repository_by_name(&state, &user, organization_id, &repository_name).await {
        Ok(repo) => repo,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = require_docker_repository(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_hosted(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_granted_action(&user, repo.id, &repository_name, "push") {
        return status.into_response();
    }
    let Ok(session_id) = Uuid::parse_str(&upload_id) else {
        return docker_error(StatusCode::BAD_REQUEST, "BLOB_UPLOAD_INVALID", "invalid upload id").into_response();
    };
    // A malformed header is treated as missing: no offset validation for this chunk.
    let expected_start = content_range.as_deref().and_then(parse_content_range_start);

    match state.patch_upload.execute(session_id, repo.id, &chunk, expected_start).await {
        Ok(total_bytes) => {
            let range_end = if total_bytes > 0 { total_bytes - 1 } else { 0 };
            (
                StatusCode::ACCEPTED,
                [
                    (header::LOCATION, format!("/v2/{repository_name}/{image_name}/blobs/uploads/{upload_id}")),
                    (HeaderName::from_static("range"), format!("0-{range_end}")),
                ],
            )
                .into_response()
        }
        Err(e) => docker_error_response(e).into_response(),
    }
}

pub async fn complete_upload(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name: String,
    upload_id: String,
    digest_query: Option<String>,
    user: DockerAuthUser,
    final_chunk: Bytes,
) -> Response {
    let repo = match require_repository_by_name(&state, &user, organization_id, &repository_name).await {
        Ok(repo) => repo,
        Err(status) => return status.into_response(),
    };
    if let Err(status) = require_docker_repository(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_hosted(&repo) {
        return status.into_response();
    }
    if let Err(status) = require_granted_action(&user, repo.id, &repository_name, "push") {
        return status.into_response();
    }
    let Some(digest_str) = digest_query else {
        return docker_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "digest query parameter is required").into_response();
    };
    let Ok(digest) = Digest::parse(&digest_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "invalid digest").into_response();
    };
    let Ok(session_id) = Uuid::parse_str(&upload_id) else {
        return docker_error(StatusCode::BAD_REQUEST, "BLOB_UPLOAD_INVALID", "invalid upload id").into_response();
    };

    // Some clients send the final bytes directly here rather than a preceding PATCH.
    if !final_chunk.is_empty() {
        if let Err(e) = state.patch_upload.execute(session_id, repo.id, &final_chunk, None).await {
            return docker_error_response(e).into_response();
        }
    }

    match state.complete_upload.execute(session_id, repo.id, &digest).await {
        Ok(()) => {
            (StatusCode::CREATED, [(header::LOCATION, format!("/v2/{repository_name}/{image_name}/blobs/{}", digest.as_str()))]).into_response()
        }
        Err(e) => docker_error_response(e).into_response(),
    }
}

pub async fn get_blob(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name_str: String,
    digest_str: String,
    user: DockerAuthUser,
) -> Response {
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
    let Ok(digest) = Digest::parse(&digest_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "invalid digest").into_response();
    };

    match state.get_blob.execute_stream(repo.id, &image_name, &digest).await {
        Ok(Some(stream)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (HeaderName::from_static("docker-content-digest"), digest.as_str().to_string()),
                // Content-addressed by digest — never changes, so a reverse proxy/CDN can serve repeat pulls without hitting the origin again.
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable".to_string()),
                (header::ETAG, format!("\"{}\"", digest.as_str())),
            ],
            Body::from_stream(stream),
        )
            .into_response(),
        Ok(None) => docker_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found").into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

/// Dedicated `HEAD` handler using `execute_exists`, so a push's existence check doesn't read an already-present blob off disk just to discard it. `Content-Length` must be set — real `docker push` errors on a HEAD without it.
pub async fn head_blob(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name_str: String,
    digest_str: String,
    user: DockerAuthUser,
) -> Response {
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
    let Ok(digest) = Digest::parse(&digest_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", "invalid digest").into_response();
    };

    match state.get_blob.execute_exists(repo.id, &image_name, &digest).await {
        Ok(Some(size_bytes)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                (header::CONTENT_LENGTH, size_bytes.to_string()),
                (HeaderName::from_static("docker-content-digest"), digest.as_str().to_string()),
            ],
        )
            .into_response(),
        Ok(None) => docker_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "blob not found").into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hangar_domain::organization::PUBLIC_ORGANIZATION_ID;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::route_test_support::{issue_test_token, seed_repository, test_state};

    const REPO_NAME_PREFIX: &str = "repo-";

    async fn hosted_repo(pool: &sqlx::PgPool) -> (Uuid, String) {
        let repository_id = Uuid::new_v4();
        seed_repository(pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        (repository_id, format!("{REPO_NAME_PREFIX}{repository_id}"))
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn starting_an_upload_without_push_scope_is_forbidden(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_monolithic_upload_then_download_round_trips_the_same_bytes(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let bytes = b"layer-bytes".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&bytes);

        let push_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(push_response.status(), StatusCode::CREATED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/blobs/{}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.to_vec(), bytes);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn getting_a_blob_carries_long_lived_cache_headers_since_a_digest_never_changes(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let bytes = b"layer-bytes".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&bytes);

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/blobs/{}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.headers().get(axum::http::header::CACHE_CONTROL).unwrap(), "public, max-age=31536000, immutable");
        assert_eq!(get_response.headers().get(axum::http::header::ETAG).unwrap(), &format!("\"{}\"", digest.as_str()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_monolithic_upload_with_a_wrong_digest_is_rejected(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest=sha256:{}", "0".repeat(64)))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(b"layer-bytes".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_chunked_upload_then_download_round_trips_the_concatenated_bytes(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let full_bytes = b"hello-world".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&full_bytes);

        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_response.status(), StatusCode::ACCEPTED);
        let location = start_response.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        // This harness mounts the router unnested, so strip the /v2 prefix.
        let upload_path = location.trim_start_matches(&format!("/v2/{repo_name}/")).to_string();

        let patch_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/{repo_name}/{upload_path}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(b"hello-".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch_response.status(), StatusCode::ACCEPTED);

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/{upload_path}?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(b"world".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/blobs/{}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.to_vec(), full_bytes);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_session_started_for_one_repository_cannot_be_completed_through_a_different_repositorys_authorization(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (victim_repository_id, victim_repo_name) = hosted_repo(&pool).await;
        let (attacker_repository_id, attacker_repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let victim_push_token = issue_test_token(&state, Uuid::new_v4(), victim_repository_id, &victim_repo_name, "myimage", &["push"]);
        let attacker_push_token = issue_test_token(&state, Uuid::new_v4(), attacker_repository_id, &attacker_repo_name, "otherimage", &["push"]);
        let app = crate::router(state);
        let bytes = b"stolen-bytes".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&bytes);

        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{victim_repo_name}/myimage/blobs/uploads/"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {victim_push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_response.status(), StatusCode::ACCEPTED);
        let location = start_response.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        let upload_path = location.trim_start_matches(&format!("/v2/{victim_repo_name}/")).to_string();
        let upload_id = upload_path.rsplit('/').next().unwrap().to_string();

        let patch_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/{attacker_repo_name}/otherimage/blobs/uploads/{upload_id}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {attacker_push_token}"))
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(patch_response.status(), StatusCode::ACCEPTED, "an upload session belonging to a different repository must not accept chunks via this route");

        let put_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{attacker_repo_name}/otherimage/blobs/uploads/{upload_id}?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {attacker_push_token}"))
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(put_response.status(), StatusCode::CREATED, "completing a foreign upload session through the wrong repository's authorization must not succeed");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_chunk_whose_content_range_matches_the_current_offset_is_accepted(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let app = crate::router(state);

        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = start_response.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        let upload_path = location.trim_start_matches(&format!("/v2/{repo_name}/")).to_string();

        let first_patch = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/{repo_name}/{upload_path}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_RANGE, "0-5")
                    .body(Body::from(b"hello-".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first_patch.status(), StatusCode::ACCEPTED);

        // A retried chunk claiming to restart at 0 bytes when 6 are already staged.
        let retried_from_zero = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/{repo_name}/{upload_path}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_RANGE, "0-4")
                    .body(Body::from(b"world".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retried_from_zero.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        // The correctly-offset chunk still succeeds afterward.
        let second_patch = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/{repo_name}/{upload_path}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_RANGE, "6-10")
                    .body(Body::from(b"world".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_patch.status(), StatusCode::ACCEPTED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn downloading_a_missing_blob_is_not_found(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/blobs/sha256:{}", "0".repeat(64)))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn head_request_for_an_existing_blob_reports_its_real_content_length(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let bytes = b"layer-bytes-for-head-check".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&bytes);

        let push_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(push_response.status(), StatusCode::CREATED);

        let head_response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/{repo_name}/myimage/blobs/{}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(head_response.status(), StatusCode::OK);
        let content_length = head_response.headers().get(axum::http::header::CONTENT_LENGTH).unwrap().to_str().unwrap().to_string();
        assert_eq!(content_length, bytes.len().to_string());
        let content_type = head_response.headers().get(axum::http::header::CONTENT_TYPE).unwrap().to_str().unwrap().to_string();
        assert_eq!(content_type, "application/octet-stream");
        let body = axum::body::to_bytes(head_response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty(), "a HEAD response must carry no body");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn head_request_for_a_missing_blob_is_not_found_with_no_body(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri(format!("/{repo_name}/myimage/blobs/sha256:{}", "0".repeat(64)))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn blob_routes_404_on_a_non_docker_format_repository(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "npm", "hosted").await;
        let repo_name = format!("{REPO_NAME_PREFIX}{repository_id}");
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/blobs/sha256:{}", "0".repeat(64)))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
