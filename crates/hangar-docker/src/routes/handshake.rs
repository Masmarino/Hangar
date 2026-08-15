use axum::extract::{RawQuery, State};
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::TypedHeader;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Basic;
use hangar_application::error::ApplicationError;
use serde_json::json;

use crate::errors::{docker_error, docker_error_response, www_authenticate_challenge};
use crate::organization_resolution::ResolvedOrganization;
use crate::state::DockerState;

pub fn router() -> Router<DockerState> {
    Router::new().route("/", get(check_version)).route("/token", get(issue_token))
}

async fn check_version(State(state): State<DockerState>, headers: axum::http::HeaderMap) -> Response {
    let authenticated = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| state.token_issuer.verify(token).is_ok());

    if authenticated {
        (StatusCode::OK, [(HeaderName::from_static("docker-distribution-api-version"), "registry/2.0")], Json(json!({}))).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, www_authenticate_challenge(&state, None))],
            Json(json!({ "errors": [{ "code": "UNAUTHORIZED", "message": "authentication required" }] })),
        )
            .into_response()
    }
}

// Real clients can send more than one `?scope=` param, but `axum::extract::Query` 400s on repeated keys — parse the raw query string instead.
fn scope_values(raw_query: Option<&str>) -> Vec<String> {
    let Some(raw_query) = raw_query else { return Vec::new() };
    form_urlencoded::parse(raw_query.as_bytes()).filter(|(key, _)| key == "scope").map(|(_, value)| value.into_owned()).collect()
}

/// Unions actions for scopes naming the same resource; keeps only the first distinct resource if more than one is requested.
fn merge_scopes(raw_scopes: &[String]) -> Option<String> {
    let mut merged: Option<hangar_domain::docker_registry::DockerScopeRequest> = None;
    for raw in raw_scopes {
        let Some(parsed) = hangar_domain::docker_registry::DockerScopeRequest::parse(raw) else { continue };
        match &mut merged {
            None => merged = Some(parsed),
            Some(existing) if existing.resource_type == parsed.resource_type && existing.name == parsed.name => {
                for action in parsed.actions {
                    if !existing.actions.contains(&action) {
                        existing.actions.push(action);
                    }
                }
            }
            Some(_) => {}
        }
    }
    merged.map(|s| format!("{}:{}:{}", s.resource_type, s.name, s.actions.join(",")))
}

async fn issue_token(
    State(state): State<DockerState>,
    resolved_org: ResolvedOrganization,
    RawQuery(raw_query): RawQuery,
    basic_auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Response {
    let merged_scope = merge_scopes(&scope_values(raw_query.as_deref()));
    let Some(TypedHeader(Authorization(basic))) = basic_auth else {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, www_authenticate_challenge(&state, merged_scope.as_deref()))],
            Json(json!({ "errors": [{ "code": "UNAUTHORIZED", "message": "missing Basic credentials" }] })),
        )
            .into_response();
    };

    match state.issue_access_token.execute(resolved_org.0.id, basic.password(), merged_scope.as_deref()).await {
        Ok(token) => Json(json!({ "token": token, "access_token": token })).into_response(),
        Err(ApplicationError::InvalidCredentials) => docker_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "invalid credentials").into_response(),
        Err(e) => docker_error_response(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum_extra::headers::HeaderMapExt;
    use hangar_domain::organization::PUBLIC_ORGANIZATION_ID;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::route_test_support::{seed_organization_admin_with_active_token, seed_permission, seed_repository, seed_user_with_active_token, test_state};

    fn basic_auth_header(password: &str) -> axum::http::HeaderValue {
        let mut headers = axum::http::HeaderMap::new();
        headers.typed_insert(Authorization::basic("ignored", password));
        headers.get(axum::http::header::AUTHORIZATION).unwrap().clone()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn version_check_without_a_token_challenges_with_bearer(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::router(test_state(pool, dir.path()).await);
        let response = app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let challenge = response.headers().get(axum::http::header::WWW_AUTHENTICATE).unwrap().to_str().unwrap();
        assert!(challenge.starts_with("Bearer "));
        assert!(challenge.contains("realm="));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn version_check_with_a_valid_token_succeeds(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let token = state.token_issuer.issue(Uuid::new_v4(), Uuid::new_v4(), false, None).unwrap();
        let app = crate::router(state);

        let response =
            app.oneshot(Request::builder().uri("/").header(axum::http::header::AUTHORIZATION, format!("Bearer {token}")).body(Body::empty()).unwrap())
                .await
                .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_without_credentials_is_unauthorized(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::router(test_state(pool, dir.path()).await);
        let response = app.oneshot(Request::builder().uri("/token").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_with_a_wrong_password_is_unauthorized(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let app = crate::router(test_state(pool, dir.path()).await);
        let response = app
            .oneshot(Request::builder().uri("/token").header(axum::http::header::AUTHORIZATION, basic_auth_header("wrong")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_with_a_valid_token_and_no_scope_issues_an_unscoped_jwt(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        seed_user_with_active_token(&pool, PUBLIC_ORGANIZATION_ID, "plaintext-token").await;
        let app = crate::router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/token")
                    .header(axum::http::header::AUTHORIZATION, basic_auth_header("plaintext-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims = state.token_issuer.verify(json["token"].as_str().unwrap()).unwrap();
        assert!(claims.granted_scope.is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_narrows_scope_to_the_users_granted_role(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let user_id = seed_user_with_active_token(&pool, PUBLIC_ORGANIZATION_ID, "plaintext-token").await;
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        seed_permission(&pool, user_id, repository_id, "read").await;
        let app = crate::router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/token?scope=repository:repo-{repository_id}/myimage:pull,push"))
                    .header(axum::http::header::AUTHORIZATION, basic_auth_header("plaintext-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims = state.token_issuer.verify(json["token"].as_str().unwrap()).unwrap();
        assert_eq!(claims.granted_scope.unwrap().actions, vec!["pull".to_string()]);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_accepts_repeated_scope_query_parameters(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        let user_id = seed_user_with_active_token(&pool, PUBLIC_ORGANIZATION_ID, "plaintext-token").await;
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        seed_permission(&pool, user_id, repository_id, "write").await;
        let app = crate::router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/token?scope=repository%3Arepo-{repository_id}%2Fmyimage%3Apull&scope=repository%3Arepo-{repository_id}%2Fmyimage%3Apull%2Cpush"
                    ))
                    .header(axum::http::header::AUTHORIZATION, basic_auth_header("plaintext-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims = state.token_issuer.verify(json["token"].as_str().unwrap()).unwrap();
        let mut actions = claims.granted_scope.unwrap().actions;
        actions.sort();
        assert_eq!(actions, vec!["pull".to_string(), "push".to_string()]);
    }

    /// Mirrors hangar-api's org-admin bypass (`hangar_api::authz::effective_repository_role`) — implicit Admin on any repository in their own org, no explicit grant needed.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn token_endpoint_grants_full_scope_to_an_organization_admin_of_the_repositorys_own_organization(pool: sqlx::PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool.clone(), dir.path()).await;
        seed_organization_admin_with_active_token(&pool, PUBLIC_ORGANIZATION_ID, "org-admin-token").await;
        let repository_id = Uuid::new_v4();
        seed_repository(&pool, PUBLIC_ORGANIZATION_ID, repository_id, "docker", "hosted").await;
        // Deliberately no `seed_permission` call — the org-admin bypass must not need one.
        let app = crate::router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/token?scope=repository:repo-{repository_id}/myimage:pull,push"))
                    .header(axum::http::header::AUTHORIZATION, basic_auth_header("org-admin-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let claims = state.token_issuer.verify(json["token"].as_str().unwrap()).unwrap();
        let mut actions = claims.granted_scope.unwrap().actions;
        actions.sort();
        assert_eq!(actions, vec!["pull".to_string(), "push".to_string()]);
    }
}
