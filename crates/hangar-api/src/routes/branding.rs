use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use crate::auth_middleware::AuthUser;
use crate::authz::require_organization_admin;
use crate::dto::{application_error_response, ErrorResponse};
use crate::organization_middleware::ResolvedOrganization;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/branding/logo", get(get_logo))
        .route("/api/branding/favicon", get(get_favicon))
        .route(
            "/api/admin/branding/logo",
            axum::routing::put(set_logo).delete(clear_logo),
        )
        .route(
            "/api/admin/branding/favicon",
            axum::routing::put(set_favicon).delete(clear_favicon),
        )
}

/// Always resolves to something — the operator's own upload, or the compiled-in default logo.
async fn get_logo(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let branding = state.get_branding.execute(resolved_org.0.id).await.map_err(|e| application_error_response("failed to get branding", e))?;
    Ok(([(header::CONTENT_TYPE, branding.logo.content_type), (header::CACHE_CONTROL, "no-cache".to_string())], branding.logo.bytes))
}

async fn get_favicon(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let branding = state.get_branding.execute(resolved_org.0.id).await.map_err(|e| application_error_response("failed to get branding", e))?;
    Ok(([(header::CONTENT_TYPE, branding.favicon.content_type), (header::CACHE_CONTROL, "no-cache".to_string())], branding.favicon.bytes))
}

/// A super-admin manages whatever org the domain resolves to; anyone else only ever manages their own.
fn target_organization_id(user: &AuthUser, resolved_org: &ResolvedOrganization) -> uuid::Uuid {
    if user.is_super_admin { resolved_org.0.id } else { user.organization_id }
}

async fn set_logo(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization, body: Bytes) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.set_branding_logo.execute(organization_id, body.to_vec()).await.map_err(|e| application_error_response("failed to set branding logo", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_logo(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.clear_branding_logo.execute(organization_id).await.map_err(|e| application_error_response("failed to clear branding logo", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_favicon(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization, body: Bytes) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.set_branding_favicon.execute(organization_id, body.to_vec()).await.map_err(|e| application_error_response("failed to set branding favicon", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_favicon(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.clear_branding_favicon.execute(organization_id).await.map_err(|e| application_error_response("failed to clear branding favicon", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;
    use uuid::Uuid;

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

    fn png_bytes() -> Vec<u8> {
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(b"fake-png-data");
        bytes
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_logo_is_publicly_readable_without_authentication(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(response.headers().get("content-type").unwrap(), "image/png");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty(), "an unconfigured instance must still serve the built-in default logo");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_favicon_is_publicly_readable_without_authentication(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/branding/favicon").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_upload_and_then_read_back_a_custom_logo(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(png_bytes()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), axum::http::StatusCode::NO_CONTENT);

        let get = app.oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(get.status(), axum::http::StatusCode::OK);
        let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.to_vec(), png_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_upload_a_logo(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(png_bytes()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn uploading_an_unsupported_format_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from("not an image"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_oversized_upload_is_rejected_before_the_application_level_size_check_would_even_see_it(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        // Bigger than both the 10 MiB router limit and the 2 MiB branding check — a 413 here
        // (not that check's 400) proves the router limit is what actually stopped it.
        let oversized = vec![0u8; 11 * 1024 * 1024];
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clearing_the_logo_reverts_to_the_default(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let default_response = app.clone().oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();
        let default_body = to_bytes(default_response.into_body(), usize::MAX).await.unwrap();

        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(png_bytes()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let delete = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete.status(), axum::http::StatusCode::NO_CONTENT);

        let get = app.oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        assert_ne!(body.to_vec(), png_bytes());
        assert_eq!(body.to_vec(), default_body.to_vec(), "must revert to the exact same built-in default the unconfigured instance already served");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_ico_favicon_upload_is_accepted(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let mut ico = vec![0x00, 0x00, 0x01, 0x00];
        ico.extend_from_slice(b"fake-ico-data");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/favicon")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(ico))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_upload_a_logo_for_their_own_organization_regardless_of_domain(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        // No `host` header — resolves to the public organization, not this admin's own.
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(png_bytes()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admins_logo_upload_does_not_affect_the_public_organizations_logo(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let default_response = app.clone().oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();
        let default_body = to_bytes(default_response.into_body(), usize::MAX).await.unwrap();

        app.clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/branding/logo")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(png_bytes()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // No host header — this GET resolves to the public organization, same as the write above did not.
        let get = app.oneshot(Request::builder().uri("/api/branding/logo").body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.to_vec(), default_body.to_vec(), "an org-admin's upload must land on their own organization, never on the public organization the request's domain happened to resolve to");
    }
}
