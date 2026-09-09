use axum::Json;
use axum::RequestPartsExt;
use axum::extract::{FromRequestParts, Path};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use hangar_domain::docker_registry::DockerGrantedScope;
use serde_json::json;
use uuid::Uuid;

use crate::errors::www_authenticate_challenge;
use crate::state::DockerState;

#[derive(Clone)]
pub struct DockerAuthUser {
    pub user_id: Uuid,
    /// Snapshot as of token issuance, not re-checked live per request.
    pub organization_id: Uuid,
    pub is_super_admin: bool,
    pub granted_scope: Option<DockerGrantedScope>,
}

/// `None` for a route with no `:repository`/`*rest` params (e.g. `/_catalog`) — falls back to the unscoped challenge, same as `GET /v2/`.
async fn scope_hint(parts: &mut Parts, state: &DockerState) -> Option<String> {
    let Path((repository, rest)): Path<(String, String)> = parts.extract_with_state(state).await.ok()?;
    let image_name = crate::routes::path::parse_operation(&rest)?.image_name().to_string();
    Some(format!("repository:{repository}/{image_name}:pull,push"))
}

/// Always challenges with the combined `pull,push` scope — `docker push` relies on this for its first, unauthenticated request. Safe: it's an upper bound, narrowed later by `IssueDockerAccessTokenUseCase`.
fn unauthorized(state: &DockerState, scope: Option<&str>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, www_authenticate_challenge(state, scope))],
        Json(json!({ "errors": [{ "code": "UNAUTHORIZED", "message": "authentication required" }] })),
    )
        .into_response()
}

impl FromRequestParts<DockerState> for DockerAuthUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &DockerState) -> Result<Self, Self::Rejection> {
        // Must run before the Bearer extraction below consumes `parts`.
        let scope = scope_hint(parts, state).await;

        let TypedHeader(Authorization(bearer)) =
            parts.extract::<TypedHeader<Authorization<Bearer>>>().await.map_err(|_| unauthorized(state, scope.as_deref()))?;
        let claims = state.token_issuer.verify(bearer.token()).map_err(|_| unauthorized(state, scope.as_deref()))?;
        Ok(DockerAuthUser {
            user_id: claims.user_id,
            organization_id: claims.organization_id,
            is_super_admin: claims.is_super_admin,
            granted_scope: claims.granted_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_test_support::test_state;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use hangar_domain::docker_registry::DockerTokenIssuerPort;
    use hangar_infrastructure::jwt_docker_token_issuer::JwtDockerTokenIssuer;
    use hangar_infrastructure::jwt_token_issuer::JwtTokenIssuer;
    use sqlx::PgPool;
    use tower::ServiceExt;

    /// No `:repository`/`*rest` params, so `DockerAuthUser` gets exercised in isolation without `dispatch.rs`'s routing machinery.
    fn router(state: DockerState) -> Router {
        async fn handler(user: DockerAuthUser) -> Json<serde_json::Value> {
            Json(json!({
                "user_id": user.user_id,
                "organization_id": user.organization_id,
                "is_super_admin": user.is_super_admin,
                "granted_scope_name": user.granted_scope.map(|s| s.name),
            }))
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    async fn request(state: DockerState, auth_header: Option<&str>) -> Response {
        let mut builder = Request::builder().uri("/");
        if let Some(value) = auth_header {
            builder = builder.header(axum::http::header::AUTHORIZATION, value);
        }
        router(state).oneshot(builder.body(Body::empty()).unwrap()).await.unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_docker_access_token_authenticates_and_maps_claims_correctly(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let user_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        let token = state.token_issuer.issue(user_id, organization_id, true, None).unwrap();

        let response = request(state, Some(&format!("Bearer {token}"))).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["user_id"], user_id.to_string());
        assert_eq!(json["organization_id"], organization_id.to_string());
        assert_eq!(json["is_super_admin"], true);
        assert!(json["granted_scope_name"].is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_token_carries_its_granted_scope_through_the_extractor(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let repository_id = Uuid::new_v4();
        let scope = DockerGrantedScope {
            resource_type: "repository".to_string(),
            name: "myrepo/myimage".to_string(),
            actions: vec!["pull".to_string()],
            granted_repository_id: Some(repository_id),
        };
        let token = state.token_issuer.issue(Uuid::new_v4(), Uuid::new_v4(), false, Some(scope)).unwrap();

        let response = request(state, Some(&format!("Bearer {token}"))).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["granted_scope_name"], "myrepo/myimage");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_missing_authorization_header_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        let response = request(state, None).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_malformed_authorization_header_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        // Wrong auth scheme entirely — `TypedHeader<Authorization<Bearer>>` extraction fails.
        let response = request(state, Some("Basic dXNlcjpwYXNz")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_garbage_bearer_token_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;

        // Not a JWT at all — three-part structural decoding fails immediately.
        let response = request(state, Some("Bearer not-a-real-jwt")).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A structurally well-formed, correctly-signed JWT — just signed with a secret this server doesn't recognize. Must be rejected exactly like garbage.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_signed_with_a_different_secret_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await; // route_test_support wires "test-secret"
        let other_issuer = JwtDockerTokenIssuer::new("a-different-secret".to_string());
        let token = other_issuer.issue(Uuid::new_v4(), Uuid::new_v4(), false, None).unwrap();

        let response = request(state, Some(&format!("Bearer {token}"))).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// A syntactically valid, correctly-shaped token whose signature has been tampered with must not verify.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_with_a_tampered_signature_is_rejected(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await;
        let token = state.token_issuer.issue(Uuid::new_v4(), Uuid::new_v4(), false, None).unwrap();
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_ne!(tampered, token, "the mutation must actually change the token");

        let response = request(state, Some(&format!("Bearer {tampered}"))).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Both issuers share the same secret, so the `typ` claim is the only thing keeping a session token from being accepted as a Docker access token.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_session_login_token_is_rejected_as_a_docker_access_token(pool: PgPool) {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(pool, dir.path()).await; // route_test_support wires "test-secret"
        let session_issuer = JwtTokenIssuer::new("test-secret".to_string());
        let token = hangar_domain::user::TokenIssuerPort::issue(&session_issuer, Uuid::new_v4(), chrono::Duration::hours(12)).unwrap();

        let response = request(state, Some(&format!("Bearer {token}"))).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
