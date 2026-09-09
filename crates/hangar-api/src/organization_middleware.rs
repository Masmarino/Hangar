use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use hangar_domain::organization::{Organization, OrganizationSlug};

use crate::state::AppState;

#[derive(Clone)]
pub struct ResolvedOrganization(pub Organization);

impl FromRequestParts<AppState> for ResolvedOrganization {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let host = parts
            .headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Strip a port if present, and lowercase — an uppercase Host header must resolve
        // the same as its lowercase form.
        let host_without_port = host.split(':').next().unwrap_or(host).to_ascii_lowercase();

        let label = host_without_port
            .strip_suffix(&format!(".{}", state.hangar_base_domain))
            .unwrap_or("");

        let org = if label.is_empty() || label == "www" {
            state
                .organizations
                .find_public()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        } else {
            let slug = OrganizationSlug::parse(label).map_err(|_| StatusCode::NOT_FOUND)?;
            state
                .organizations
                .find_by_slug(&slug)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::NOT_FOUND)?
        };

        Ok(ResolvedOrganization(org))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::AppState;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use hangar_domain::organization::OrganizationSlug;
    use tower::ServiceExt;

    // This crate has no shared test Config helper — every route test module defines its own
    // local copy (see crates/hangar-api/src/routes/repositories.rs's own `test_config()` for
    // the established pattern this mirrors).
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

    fn router(state: AppState) -> Router {
        async fn handler(ResolvedOrganization(org): ResolvedOrganization) -> String {
            org.slug.as_str().to_string()
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_empty_host_label_resolves_to_the_public_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "hangar.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "public".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_www_host_label_resolves_to_the_public_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "www.hangar.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_known_organization_slug_resolves_to_that_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state
            .organizations
            .create(&Organization {
                id: uuid::Uuid::new_v4(),
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "acme.hangar.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "acme".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_unknown_organization_slug_is_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "nope.hangar.localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_port_suffix_on_the_host_header_is_ignored(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "hangar.localhost:8080")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_uppercase_host_header_still_resolves_the_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state
            .organizations
            .create(&Organization {
                id: uuid::Uuid::new_v4(),
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let app = router(state);
        // DNS is case-insensitive, so a real client can send an uppercase Host header — it
        // must resolve exactly like the lowercase form, not silently fall through to the
        // public organization.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", "ACME.HANGAR.LOCALHOST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "acme".as_bytes());
    }
}
