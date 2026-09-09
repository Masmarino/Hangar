use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::authz::{require_organization_admin, require_super_admin};
use crate::dto::{application_error_response, ErrorResponse};
use crate::organization_middleware::ResolvedOrganization;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", get(get_user).delete(delete_user))
        .route("/api/users/{id}/super-admin", axum::routing::put(set_super_admin))
        .route("/api/users/{id}/resend-invitation", axum::routing::post(resend_invitation))
        .route("/api/users/lookup", get(lookup_user))
        .route("/api/users/search", get(search_users))
        .route("/api/users/{id}/permissions", get(list_user_permissions))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    is_super_admin: bool,
    #[serde(default)]
    is_organization_admin: bool,
}

#[derive(Serialize)]
struct UserResponse {
    id: Uuid,
    username: String,
    is_super_admin: bool,
    organization_id: Uuid,
    email: Option<String>,
    /// `true` until the invitation link is used to set a real password.
    invitation_pending: bool,
}

/// An organization admin only sees their own organization's users, not everyone's.
async fn list_users(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<UserResponse>>, (StatusCode, Json<ErrorResponse>)> {
    if !user.is_super_admin && !user.is_organization_admin {
        return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "forbidden".to_string() })));
    }
    let users = state.users.list_all().await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let users: Vec<_> = if user.is_super_admin { users } else { users.into_iter().filter(|u| u.organization_id == user.organization_id).collect() };
    let user_ids: Vec<Uuid> = users.iter().map(|u| u.id).collect();
    let pending = state
        .user_invitations
        .list_pending_user_ids(&user_ids)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let result = users
        .into_iter()
        .map(|u| UserResponse {
            invitation_pending: pending.contains(&u.id),
            id: u.id,
            username: u.username.as_str().to_string(),
            is_super_admin: u.is_super_admin,
            organization_id: u.organization_id,
            email: u.email,
        })
        .collect();
    Ok(Json(result))
}

/// An organization admin can view any user in their own organization, same as a super-admin.
async fn get_user(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<UserResponse>, (StatusCode, Json<ErrorResponse>)> {
    let target = state
        .users
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() })))?;
    require_organization_admin(&user, target.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let invitation_pending = state
        .user_invitations
        .find_by_user_id(target.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .is_some();
    Ok(Json(UserResponse {
        id: target.id,
        username: target.username.as_str().to_string(),
        is_super_admin: target.is_super_admin,
        organization_id: target.organization_id,
        email: target.email,
        invitation_pending,
    }))
}

async fn create_user(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let id = state
        .invite_user
        .execute(resolved_org.0.id, body.is_organization_admin, &body.username, &body.email, body.is_super_admin)
        .await
        .map_err(|e| application_error_response("failed to invite user", e))?;
    Ok((
        StatusCode::CREATED,
        Json(UserResponse {
            id,
            username: body.username,
            is_super_admin: body.is_super_admin,
            organization_id: resolved_org.0.id,
            email: Some(body.email),
            invitation_pending: true,
        }),
    ))
}

/// Same reach as get_user, but an organization admin can never act on a super-admin account even in their own org — that's a global privilege, not theirs to touch.
async fn resend_invitation(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if !user.is_super_admin {
        let target = state
            .users
            .find_by_id(id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
            .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() })))?;
        require_organization_admin(&user, target.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
        if target.is_super_admin {
            return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "forbidden".to_string() })));
        }
    }
    state.resend_invitation.execute(id).await.map_err(|e| application_error_response("failed to resend invitation", e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Same super-admin-target carve-out as resend_invitation.
async fn delete_user(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if !user.is_super_admin {
        let target = state
            .users
            .find_by_id(id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
            .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() })))?;
        require_organization_admin(&user, target.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
        if target.is_super_admin {
            return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "forbidden".to_string() })));
        }
    }
    state.delete_user.execute(id).await.map_err(|e| application_error_response("failed to delete user", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SetSuperAdminRequest {
    is_super_admin: bool,
}

async fn set_super_admin(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetSuperAdminRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.set_super_admin.execute(id, body.is_super_admin).await.map_err(|e| application_error_response("failed to change super-admin status", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LookupQuery {
    username: String,
}

/// No `is_super_admin` — this is open to every authenticated caller.
#[derive(Serialize)]
struct UserLookupResponse {
    id: Uuid,
    username: String,
}

/// Scoped to the request's resolved organization, not the caller's own — without this, any authenticated user could enumerate other organizations' usernames.
async fn lookup_user(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Query(params): Query<LookupQuery>,
) -> Result<Json<UserLookupResponse>, (StatusCode, Json<ErrorResponse>)> {
    let not_found = || (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() }));
    let username = hangar_domain::user::Username::parse(&params.username).map_err(|_| not_found())?;
    let target = state
        .users
        .find_by_username(&username)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or_else(not_found)?;
    if !user.is_super_admin && target.organization_id != resolved_org.0.id {
        return Err(not_found());
    }
    Ok(Json(UserLookupResponse { id: target.id, username: target.username.as_str().to_string() }))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

const SEARCH_RESULT_LIMIT: usize = 10;

/// Same privacy contract as `lookup_user`. Empty `q` returns no results.
async fn search_users(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<UserLookupResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let query = params.q.trim().to_lowercase();
    if query.is_empty() {
        return Ok(Json(vec![]));
    }
    let mut matches: Vec<_> = state
        .users
        .list_all()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .into_iter()
        .filter(|u| user.is_super_admin || u.organization_id == resolved_org.0.id)
        .filter(|u| u.username.as_str().to_lowercase().contains(&query))
        .collect();
    matches.sort_by(|a, b| a.username.as_str().cmp(b.username.as_str()));
    matches.truncate(SEARCH_RESULT_LIMIT);
    Ok(Json(matches.into_iter().map(|u| UserLookupResponse { id: u.id, username: u.username.as_str().to_string() }).collect()))
}

#[derive(Serialize)]
struct UserPermissionEntryResponse {
    repository_id: Uuid,
    repository_name: String,
    format: hangar_domain::package_repository::RepositoryFormat,
    role: hangar_domain::permission::Role,
}

/// Same reach as get_user (view-only, so no super-admin-target carve-out is needed here).
async fn list_user_permissions(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<UserPermissionEntryResponse>>, (StatusCode, Json<ErrorResponse>)> {
    if !user.is_super_admin {
        let target = state
            .users
            .find_by_id(id)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
            .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() })))?;
        require_organization_admin(&user, target.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    }
    let entries = state
        .permissions
        .list_for_user(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let repos: std::collections::HashMap<Uuid, _> = state
        .repositories
        .list_all()
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .into_iter()
        .map(|r| (r.id, r))
        .collect();
    let result = entries
        .into_iter()
        .filter_map(|(repository_id, role)| {
            repos.get(&repository_id).map(|repo| UserPermissionEntryResponse { repository_id, repository_name: repo.name.clone(), format: repo.format, role })
        })
        .collect();
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use hangar_domain::package_repository::{RepositoryFormat, RepositoryType};
    use hangar_domain::permission::Role;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn create_org(state: &AppState, id: Uuid, slug: &str) {
        state
            .organizations
            .create(&hangar_domain::organization::Organization {
                id,
                slug: hangar_domain::organization::OrganizationSlug::parse(slug).unwrap(),
                display_name: slug.to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }

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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_create_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"newuser","email":"newuser@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["email"], "newuser@example.com");
        assert_eq!(json["invitation_pending"], true);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_newly_invited_user_shows_as_pending_in_the_user_list(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"invitee","email":"invitee@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = app
            .oneshot(Request::builder().uri("/api/users").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let invitee = json.as_array().unwrap().iter().find(|u| u["username"] == "invitee").unwrap();
        assert_eq!(invitee["invitation_pending"], true);
        let admin = json.as_array().unwrap().iter().find(|u| u["username"] == "admin").unwrap();
        assert_eq!(admin["invitation_pending"], false, "a user created outside the invitation flow must not show as pending");
    }

    /// No SMTP configured, so this 500s — verifies authorization is reached, not 403.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_resend_an_invitation(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"invitee","email":"invitee@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(create_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let user_id = json["id"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{user_id}/resend-invitation"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn resending_an_invitation_for_an_unknown_user_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{}/resend-invitation", Uuid::new_v4()))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_resend_an_invitation(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "victim", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{target_id}/resend-invitation"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_create_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"username":"newuser","email":"newuser@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_delete_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"doomed","email":"doomed@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_response.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(create_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let user_id = json["id"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{user_id}"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_get_a_single_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/users/{target_id}"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "florian");
        assert_eq!(json["is_super_admin"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn getting_an_unknown_user_returns_404(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/users/{}", Uuid::new_v4()))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_get_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/users/{target_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_the_last_super_admin_is_rejected_with_409(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{admin_id}"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_be_deleted_when_another_one_remains(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let second_admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "second-admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{second_admin_id}"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_duplicate_username_keeps_its_specific_error_message(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"florian","email":"florian2@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "username already taken");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_invalid_username_keeps_its_specific_error_message(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"x","email":"x@example.com","is_super_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().starts_with("invalid username"), "got {}", json["error"]);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_delete_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "victim", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{target_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lookup_finds_an_existing_username(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/lookup?username=florian")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "florian");
        assert!(json["id"].is_string());
        assert!(json.get("is_super_admin").is_none(), "lookup must not expose admin status: {json}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn search_matches_a_username_substring_case_insensitively(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian-simon", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "someone-else", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/search?q=FLOR")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let results: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.as_array().unwrap().len(), 1);
        assert_eq!(results[0]["username"], "florian-simon");
        assert!(results[0].get("is_super_admin").is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn search_returns_no_results_for_an_empty_query(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/search?q=")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let results: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.as_array().unwrap().len(), 0);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn search_caps_results_at_the_limit(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        for i in 0..15 {
            state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), &format!("match-user-{i:02}"), "sup3r-s3cret!", false).await.unwrap();
        }
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/search?q=match")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let results: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.as_array().unwrap().len(), 10);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lookup_returns_404_for_an_unknown_username(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/lookup?username=ghost")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lookup_cannot_find_a_user_in_another_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        // Non-super-admin caller in the public organization.
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "public-regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("public-regular", "sup3r-s3cret!").await.unwrap();
        // The target username exists, but only in a different ("acme") organization.
        state.create_user.execute(acme_id, "acme-florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/lookup?username=acme-florian")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn search_does_not_enumerate_usernames_from_another_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "public-regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("public-regular", "sup3r-s3cret!").await.unwrap();
        state.create_user.execute(acme_id, "acme-florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/search?q=flor")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let results: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(results.as_array().unwrap().len(), 0, "must not leak a username from another organization: {results}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_still_look_up_a_user_in_another_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        state.create_user.execute(acme_id, "acme-florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/users/lookup?username=acme-florian")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lists_a_users_permissions_with_repository_name_and_format(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Write, admin_id).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/users/{member_id}/permissions"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let entries: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries[0]["repository_id"], repo_id.to_string());
        assert_eq!(entries[0]["repository_name"], "my-repo");
        assert_eq!(entries[0]["format"], "npm");
        assert_eq!(entries[0]["role"], "write");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_list_another_users_permissions(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/users/{member_id}/permissions"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    fn set_super_admin_request(token: &str, id: Uuid, is_super_admin: bool) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri(format!("/api/users/{id}/super-admin"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(format!(r#"{{"is_super_admin":{is_super_admin}}}"#)))
            .unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_promote_a_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(set_super_admin_request(&admin_token, target_id, true)).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn demoting_the_last_super_admin_is_rejected_with_409(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(set_super_admin_request(&admin_token, admin_id, false)).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_change_super_admin_status(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let target_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "victim", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(set_super_admin_request(&token, target_id, true)).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    /// The invited-into organization must follow the request's `Host` header, not the
    /// calling super-admin's own organization.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn inviting_a_user_targets_the_hosts_organization_not_the_callers(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header("host", "acme.hangar.localhost")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"username":"acme-admin","email":"acme-admin@example.com","is_super_admin":false,"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let user_id = Uuid::parse_str(json["id"].as_str().unwrap()).unwrap();

        let created = state.users.find_by_id(user_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, acme_id, "must be invited into the Host's organization, not the caller's own");
        assert!(created.is_organization_admin);
        assert_eq!(json["organization_id"], acme_id.to_string(), "the response must report the organization the user was actually created in");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn listing_users_reports_each_users_organization_id(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/users").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let acme_user = json.as_array().unwrap().iter().find(|u| u["username"] == "acme-user").unwrap();
        assert_eq!(acme_user["organization_id"], acme_id.to_string());
        let admin = json.as_array().unwrap().iter().find(|u| u["username"] == "admin").unwrap();
        assert_eq!(admin["organization_id"], "00000000-0000-0000-0000-000000000001");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_list_only_their_own_organizations_users(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
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
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        // A super-admin in a different organization must never show up in the org-admin's view.
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/users").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let usernames: Vec<&str> = json.as_array().unwrap().iter().map(|u| u["username"].as_str().unwrap()).collect();
        assert_eq!(usernames.len(), 2, "must see only their own organization's users: {usernames:?}");
        assert!(usernames.contains(&"acme-admin"));
        assert!(usernames.contains(&"acme-user"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_list_users(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/users").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    // --- An organization admin's reach into their own organization's users ---

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_get_a_user_in_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/users/{member_id}")).header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "acme-user");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_get_a_user_in_a_different_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let other_user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "other-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/users/{other_user_id}")).header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND, "must not reveal whether the user exists outside their own organization");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_delete_a_regular_user_in_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{member_id}"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        assert!(state.users.find_by_id(member_id).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_delete_a_user_in_a_different_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let other_user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "other-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{other_user_id}"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_delete_a_super_admin_even_in_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let super_admin_in_acme_id = state.create_user.execute(acme_id, "acme-super-admin", "sup3r-s3cret!", true).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/users/{super_admin_in_acme_id}"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "super-admin is a global privilege, not something an organization admin's reach extends to");
        assert!(state.users.find_by_id(super_admin_in_acme_id).await.unwrap().is_some());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_resend_an_invitation_for_their_own_organizations_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{member_id}/resend-invitation"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // No SMTP configured, so this 500s past authorization — what matters is it isn't 403/404.
        assert_ne!(response.status(), axum::http::StatusCode::FORBIDDEN);
        assert_ne!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_resend_an_invitation_for_a_super_admin(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let super_admin_in_acme_id = state.create_user.execute(acme_id, "acme-super-admin", "sup3r-s3cret!", true).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/users/{super_admin_in_acme_id}/resend-invitation"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_change_super_admin_status_even_for_their_own_organizations_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(set_super_admin_request(&org_admin_token, member_id, true)).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "granting instance-wide super-admin is not an organization-scoped right");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_list_permissions_for_their_own_organizations_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Write, org_admin_id).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/users/{member_id}/permissions")).header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
        assert_eq!(json[0]["repository_name"], "acme-repo");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_list_permissions_for_a_user_in_a_different_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = Uuid::new_v4();
        create_org(&state, acme_id, "acme").await;
        let org_admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let other_user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "other-user", "sup3r-s3cret!", false).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/users/{other_user_id}/permissions")).header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}
