use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::RequestPartsExt;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use chrono::{DateTime, Utc};
use hangar_domain::user::{TokenIssuerPort, User};
use uuid::Uuid;

use crate::state::AppState;

/// Re-read from the database on every request, so a deleted user's token stops working.
#[derive(Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            parts.extract::<TypedHeader<Authorization<Bearer>>>().await.map_err(|_| StatusCode::UNAUTHORIZED)?;

        let verified = state.token_issuer.verify(bearer.token()).map_err(|_| StatusCode::UNAUTHORIZED)?;
        let user: User = state
            .users
            .find_by_id(verified.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Second-granularity: JWT `iat` has no sub-second precision, unlike tokens_valid_after.
        if verified.issued_at.timestamp() < user.tokens_valid_after.timestamp() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        Ok(AuthUser {
            id: user.id,
            username: user.username.as_str().to_string(),
            is_super_admin: user.is_super_admin,
            is_organization_admin: user.is_organization_admin,
            organization_id: user.organization_id,
            created_at: user.created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::AppState;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    // Same local pattern as every other route/middleware test module (see organization_middleware.rs).
    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            jwt_secret: "test-secret".to_string(),
            secrets_encryption_key: "test-secret".to_string(),
            storage_root: std::env::temp_dir().to_string_lossy().to_string(),
            bind_addr: "0.0.0.0:0".to_string(),
            cors_allowed_origin: None,
            docker_token_realm: "http://localhost/v2/token".to_string(),
            public_url: "http://localhost:4200".to_string(),
            db_max_connections: hangar_infrastructure::postgres::DEFAULT_DB_MAX_CONNECTIONS,
            hangar_base_domain: "hangar.localhost".to_string(),
        }
    }

    const PUBLIC_ORG: &str = "00000000-0000-0000-0000-000000000001";

    fn router(state: AppState) -> Router {
        async fn handler(user: AuthUser) -> String {
            user.username
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_valid_token_for_an_existing_user_succeeds(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str(PUBLIC_ORG).unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.token_issuer.issue(user_id, chrono::Duration::hours(12)).unwrap();
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "florian".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_missing_authorization_header_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_malformed_authorization_header_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);

        // Neither a well-formed JWT nor even the right scheme.
        let response = app.oneshot(Request::builder().uri("/").header("authorization", "Bearer not-a-jwt").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_bearer_authorization_scheme_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", "Basic dXNlcjpwYXNz").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_expired_token_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str(PUBLIC_ORG).unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        // Well past the ~60s clock-skew leeway jsonwebtoken allows.
        let token = state.token_issuer.issue(user_id, chrono::Duration::seconds(-300)).unwrap();
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // Verifies this file's own doc comment on AuthUser.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_for_a_deleted_user_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str(PUBLIC_ORG).unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.token_issuer.issue(user_id, chrono::Duration::hours(12)).unwrap();
        state.delete_user.execute(user_id).await.unwrap();
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a still-validly-signed token for a deleted user must not authenticate");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_issued_before_a_password_change_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str(PUBLIC_ORG).unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.token_issuer.issue(user_id, chrono::Duration::hours(12)).unwrap();

        // Force a real gap past iat's whole-second precision, or the ordering is ambiguous.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        state.users.update_password(user_id, "new-hash".to_string()).await.unwrap();
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a token issued before a password change must be rejected");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_token_issued_after_a_password_change_still_works(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str(PUBLIC_ORG).unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();

        state.users.update_password(user_id, "new-hash".to_string()).await.unwrap();
        let token = state.token_issuer.issue(user_id, chrono::Duration::hours(12)).unwrap();
        let app = router(state);

        let response = app.oneshot(Request::builder().uri("/").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK, "a token issued after a password change must remain valid");
    }
}
