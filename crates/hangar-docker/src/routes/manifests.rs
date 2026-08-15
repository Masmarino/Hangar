use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use hangar_domain::docker_registry::{Digest, DockerImageName, DockerMediaType};
use uuid::Uuid;

use crate::auth::DockerAuthUser;
use crate::authz::{require_docker_repository, require_granted_action, require_hosted, require_repository_by_name};
use crate::errors::{docker_error, docker_error_response};
use crate::state::DockerState;

pub async fn put_manifest(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name_str: String,
    reference: String,
    content_type: Option<String>,
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
    let Ok(image_name) = DockerImageName::parse(&image_name_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "invalid image name").into_response();
    };
    // Must be rejected, not silently downgraded to DockerV2Manifest — would mis-store an OCI index as a single-image manifest.
    let Ok(media_type) = DockerMediaType::parse(content_type.as_deref().unwrap_or("")) else {
        return docker_error(StatusCode::BAD_REQUEST, "MANIFEST_INVALID", "missing or unrecognized manifest Content-Type").into_response();
    };

    match state.put_manifest.execute(repo.id, &image_name, &reference, media_type, &body, user.user_id).await {
        Ok(digest) => {
            // Only a tagged push is scanned — a digest-only push (multi-arch buildx) isn't user-visible.
            // Fire-and-forget: must not hold up the response.
            if Digest::parse(&reference).is_err() {
                let scan = state.scan_docker_image.clone();
                let scan_repo_id = repo.id;
                let scan_image_name = image_name.clone();
                let scan_tag = reference.clone();
                let scan_triggered_by = user.user_id;
                tokio::spawn(async move {
                    let _ = scan.execute(scan_repo_id, &scan_image_name, &scan_tag, scan_triggered_by).await;
                });
            }
            (
                StatusCode::CREATED,
                [
                    (header::LOCATION, format!("/v2/{repository_name}/{image_name_str}/manifests/{}", digest.as_str())),
                    (HeaderName::from_static("docker-content-digest"), digest.as_str().to_string()),
                ],
            )
                .into_response()
        }
        Err(e) => docker_error_response(e).into_response(),
    }
}

pub async fn get_manifest(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name_str: String,
    reference: String,
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

    match state.get_manifest.execute(repo.id, &image_name, &reference).await {
        Ok(Some(manifest)) => {
            if repo.repo_type == hangar_domain::package_repository::RepositoryType::Proxy {
                // Best-effort — a failed cache write must not fail the pull.
                let _ = state.cache_proxied_manifest.execute(&manifest).await;
            }
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(manifest.media_type.as_str()).unwrap_or(HeaderValue::from_static("application/octet-stream")));
            headers.insert(
                HeaderName::from_static("docker-content-digest"),
                HeaderValue::from_str(manifest.digest.as_str()).unwrap_or(HeaderValue::from_static("")),
            );
            headers.insert(header::ETAG, HeaderValue::from_str(&format!("\"{}\"", manifest.digest.as_str())).unwrap_or(HeaderValue::from_static("\"\"")));
            // Only a request BY digest is guaranteed immutable — a tag can be re-pushed at any time.
            if Digest::parse(&reference).is_ok() {
                headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
            }
            (StatusCode::OK, headers, manifest.body).into_response()
        }
        Ok(None) => docker_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found").into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

pub async fn delete_manifest(
    state: DockerState,
    organization_id: Uuid,
    repository_name: String,
    image_name_str: String,
    reference: String,
    user: DockerAuthUser,
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
    let Ok(image_name) = DockerImageName::parse(&image_name_str) else {
        return docker_error(StatusCode::BAD_REQUEST, "NAME_INVALID", "invalid image name").into_response();
    };

    // A tag reference is also valid here; resolve it to a digest first.
    let digest = match Digest::parse(&reference) {
        Ok(digest) => digest,
        Err(_) => match state.get_manifest.execute(repo.id, &image_name, &reference).await {
            Ok(Some(manifest)) => manifest.digest,
            Ok(None) => return docker_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "manifest not found").into_response(),
            Err(e) => return docker_error_response(e).into_response(),
        },
    };

    match state.delete_manifest.execute(repo.id, &image_name, &digest, user.user_id).await {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
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

    async fn hosted_repo(pool: &sqlx::PgPool) -> (Uuid, String) {
        let repository_id = Uuid::new_v4();
        seed_repository(pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        (repository_id, format!("repo-{repository_id}"))
    }

    fn manifest_body(config_digest: &Digest) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": { "digest": config_digest.as_str() },
            "layers": []
        }))
        .unwrap()
    }

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
    async fn pushing_a_manifest_by_tag_then_pulling_it_back_round_trips(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let config_digest = push_config_blob(&app, &repo_name, &push_token, b"round-trip-config-bytes").await;
        let body = manifest_body(&config_digest);

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let returned = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        // Byte-exact: docker pull recomputes and compares Docker-Content-Digest.
        assert_eq!(returned.to_vec(), body);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_tag_reference_carries_an_etag_but_no_long_lived_cache_control_unlike_a_digest_reference(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let config_digest = push_config_blob(&app, &repo_name, &push_token, b"cache-header-config-bytes").await;
        let body = manifest_body(&config_digest);

        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);
        let digest = put_response.headers().get(HeaderName::from_static("docker-content-digest")).unwrap().to_str().unwrap().to_string();

        let by_tag = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(by_tag.headers().get(header::ETAG).is_some(), "a tag reference must still carry an ETag for conditional requests");
        assert!(by_tag.headers().get(header::CACHE_CONTROL).is_none(), "a tag can be reassigned — must not be cached long-lived");

        let by_digest = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/{digest}"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(by_digest.headers().get(header::CACHE_CONTROL).unwrap(), "public, max-age=31536000, immutable");
        assert_eq!(by_digest.headers().get(header::ETAG).unwrap(), &format!("\"{digest}\""));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn pushing_a_manifest_over_the_repositorys_quota_is_rejected(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        sqlx::query!("UPDATE package_repository_projections SET quota_bytes = $1 WHERE id = $2", 5_i64, repository_id).execute(&pool).await.unwrap();
        let repo_name = format!("repo-{repository_id}");
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let app = crate::router(state);
        let config_digest = push_config_blob(&app, &repo_name, &push_token, b"a config blob larger than the quota").await;
        let body = manifest_body(&config_digest);

        let put_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(put_response.status(), StatusCode::INSUFFICIENT_STORAGE);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn pushing_without_push_scope_is_forbidden(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);
        let config_digest = Digest::of(b"unused-config-bytes");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(manifest_body(&config_digest)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn pushing_a_manifest_with_missing_or_unrecognized_content_type_is_rejected(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let app = crate::router(state);
        let config_digest = Digest::of(b"unused-config-bytes");
        let body = manifest_body(&config_digest);

        let no_content_type = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_content_type.status(), StatusCode::BAD_REQUEST);

        let garbage_content_type = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/x-not-a-real-manifest-type")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(garbage_content_type.status(), StatusCode::BAD_REQUEST);
    }

    /// Without its own cap a manifest would ride on the router's 2 GB blob-sized `DefaultBodyLimit`, letting a pusher force a huge JSON parse.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn pushing_an_oversized_manifest_is_rejected_before_it_would_ever_be_parsed(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push"]);
        let app = crate::router(state);
        // Bigger than the manifest limit, well under the blob limit — a 413 proves the manifest-specific cap stopped it.
        let oversized = vec![b' '; 11 * 1024 * 1024];

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn pulling_a_missing_manifest_is_not_found(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/nonexistent"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_a_pushed_manifest_by_tag_then_pulling_it_is_not_found(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push", "pull"]);
        let app = crate::router(state);
        let config_digest = push_config_blob(&app, &repo_name, &push_token, b"delete-round-trip-config-bytes").await;

        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(manifest_body(&config_digest)))
                    .unwrap(),
            )
            .await
            .unwrap();

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::ACCEPTED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn manifest_routes_404_on_a_non_docker_format_repository(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "npm", "hosted").await;
        let repo_name = format!("repo-{repository_id}");
        let state = test_state(pool, dir.path()).await;
        let pull_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {pull_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // Deleting a manifest list must not touch its members' blob refs — it never incremented them.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_a_manifest_list_does_not_touch_its_members_blob_references(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let (repository_id, repo_name) = hosted_repo(&pool).await;
        let state = test_state(pool, dir.path()).await;
        let push_token = issue_test_token(&state, Uuid::new_v4(), repository_id, &repo_name, "myimage", &["push", "pull"]);
        let app = crate::router(state);

        let config_a = push_config_blob(&app, &repo_name, &push_token, b"member-a-config-bytes").await;
        let body_a = manifest_body(&config_a);
        let digest_a = Digest::of(&body_a);
        let put_a = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/{}", digest_a.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body_a))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_a.status(), StatusCode::CREATED);

        let config_b = push_config_blob(&app, &repo_name, &push_token, b"member-b-config-bytes").await;
        let body_b = manifest_body(&config_b);
        let digest_b = Digest::of(&body_b);
        let put_b = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/{}", digest_b.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body_b))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_b.status(), StatusCode::CREATED);

        let index_body = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                { "digest": digest_a.as_str(), "mediaType": "application/vnd.docker.distribution.manifest.v2+json" },
                { "digest": digest_b.as_str(), "mediaType": "application/vnd.docker.distribution.manifest.v2+json" },
            ]
        }))
        .unwrap();
        let put_index = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.oci.image.index.v1+json")
                    .body(Body::from(index_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_index.status(), StatusCode::CREATED);

        let delete_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            delete_response.status(),
            StatusCode::ACCEPTED,
            "deleting the index must succeed and must NOT decrement member blob refs it never incremented"
        );

        for member_config_digest in [&config_a, &config_b] {
            let blob_response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!("/{repo_name}/myimage/blobs/{}", member_config_digest.as_str()))
                        .header(axum::http::header::AUTHORIZATION, format!("Bearer {push_token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                blob_response.status(),
                StatusCode::OK,
                "member manifest's blob must survive deleting the index that pointed at the member"
            );
        }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_repository_in_the_requested_organization_is_reachable_via_its_own_subdomain(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::route_test_support::test_state(pool.clone(), dir.path()).await;

        // Proves the positive case: a non-public org's own Host header resolves to its own data.
        let acme_id = Uuid::new_v4();
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

        let repo_id = Uuid::new_v4();
        crate::route_test_support::seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let acme_user_id = crate::route_test_support::seed_user_with_active_token(&pool, acme_id, "acme-plaintext-token").await;
        let token = crate::route_test_support::issue_test_token_for_org(&state, acme_user_id, acme_id, false, repo_id, &repo_name, "myimage", &["push", "pull"]);
        let app = crate::router(state);

        let config_bytes = b"acme-own-subdomain-config-bytes";
        let config_digest = Digest::of(config_bytes);
        let blob_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", config_digest.as_str()))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::from(config_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blob_response.status(), StatusCode::CREATED);

        let body = manifest_body(&config_digest);
        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);

        let get_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let returned = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        // Byte-exact: proves the manifest actually pushed under "acme" was the one returned.
        assert_eq!(returned.to_vec(), body);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_manifest_in_one_organizations_repository_is_not_reachable_from_another_organization(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::route_test_support::test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
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
        let other_id = Uuid::new_v4();
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

        let repo_id = Uuid::new_v4();
        crate::route_test_support::seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
        let other_user_id = crate::route_test_support::seed_user_with_active_token(&pool, other_id, "plaintext-token").await;
        let token = crate::route_test_support::issue_test_token(&state, other_user_id, repo_id, &format!("repo-{repo_id}"), "myimage", &["pull"]);
        let app = crate::router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/repo-{repo_id}/myimage/manifests/latest"))
                    .header("host", "other.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// Unlike the isolation test above, this token's embedded org differs but the request targets the repository's OWNING org — only an explicit organization check can reject it.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_holders_own_organization_must_match_even_with_a_valid_granted_scope(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::route_test_support::test_state(pool.clone(), dir.path()).await;

        let acme_id = Uuid::new_v4();
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
        let other_id = Uuid::new_v4();
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

        let repo_id = Uuid::new_v4();
        crate::route_test_support::seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
        let repo_name = format!("repo-{repo_id}");
        let app = crate::router(state.clone());

        // Push a real manifest first, so the assertion below is explained by the org check, not a missing manifest.
        let acme_user_id = crate::route_test_support::seed_user_with_active_token(&pool, acme_id, "acme-owns-this-manifest").await;
        let acme_token = crate::route_test_support::issue_test_token_for_org(&state, acme_user_id, acme_id, false, repo_id, &repo_name, "myimage", &["push", "pull"]);
        let config_bytes = b"cross-org-replay-config-bytes";
        let config_digest = Digest::of(config_bytes);
        let blob_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/{repo_name}/myimage/blobs/uploads/?digest={}", config_digest.as_str()))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {acme_token}"))
                    .body(Body::from(config_bytes.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blob_response.status(), StatusCode::CREATED);
        let manifest_bytes = manifest_body(&config_digest);
        let put_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {acme_token}"))
                    .header(axum::http::header::CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(manifest_bytes.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_response.status(), StatusCode::CREATED);

        // Sanity check: acme's own token can fetch the manifest it just pushed.
        let acme_get = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {acme_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(acme_get.status(), StatusCode::OK, "sanity check: the pushed manifest must be fetchable by its own organization");

        // Holder's org is "other", but the granted scope is a real "pull" on acme's repository — a stale cross-org grant.
        let other_token = crate::route_test_support::issue_test_token_for_org(&state, Uuid::new_v4(), other_id, false, repo_id, &repo_name, "myimage", &["pull"]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/{repo_name}/myimage/manifests/latest"))
                    .header("host", "acme.hangar.localhost")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {other_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "a valid granted scope on a manifest that genuinely exists must not be enough to cross an organization boundary"
        );
    }
}
