use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::authz::{require_organization_admin, require_super_admin};
use crate::dto::{application_error_response, ErrorResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/organizations", post(create_organization).get(list_organizations))
        .route("/api/organizations/:id", get(get_organization))
        .route("/api/organizations/:id/users", get(list_organization_members).post(invite_organization_member))
        .route("/api/organizations/:id/users/:user_id/organization-admin", axum::routing::put(set_organization_member_admin))
        .route(
            "/api/organizations/:id/identity-provider",
            get(get_identity_provider).put(set_identity_provider).delete(clear_identity_provider),
        )
}

#[derive(Deserialize)]
struct CreateOrganizationRequest {
    slug: String,
    display_name: String,
}

#[derive(Serialize)]
struct OrganizationResponse {
    id: Uuid,
    slug: String,
    display_name: String,
    is_public: bool,
}

async fn create_organization(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let id = state
        .create_organization
        .execute(&body.slug, &body.display_name)
        .await
        .map_err(|e| application_error_response("failed to create organization", e))?;
    Ok((StatusCode::CREATED, Json(OrganizationResponse { id, slug: body.slug, display_name: body.display_name, is_public: false })))
}

async fn list_organizations(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<OrganizationResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let all = state.organizations.list_all().await.map_err(|e| application_error_response("failed to list organizations", e.into()))?;
    Ok(Json(all.into_iter().map(|o| OrganizationResponse { id: o.id, slug: o.slug.as_str().to_string(), display_name: o.display_name, is_public: o.is_public }).collect()))
}

async fn get_organization(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<OrganizationResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let org = state
        .organizations
        .find_by_id(id)
        .await
        .map_err(|e| application_error_response("failed to get organization", e.into()))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "organization not found".to_string() })))?;
    Ok(Json(OrganizationResponse { id: org.id, slug: org.slug.as_str().to_string(), display_name: org.display_name, is_public: org.is_public }))
}

#[derive(Serialize)]
struct OrganizationMemberResponse {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_organization_admin: bool,
    invitation_pending: bool,
}

async fn list_organization_members(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<Vec<OrganizationMemberResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let members: Vec<_> = state
        .users
        .list_all()
        .await
        .map_err(|e| application_error_response("failed to list organization members", e.into()))?
        .into_iter()
        .filter(|u| u.organization_id == id)
        .collect();
    let member_ids: Vec<Uuid> = members.iter().map(|u| u.id).collect();
    let pending = state
        .user_invitations
        .list_pending_user_ids(&member_ids)
        .await
        .map_err(|e| application_error_response("failed to list pending invitations", e.into()))?;
    Ok(Json(
        members
            .into_iter()
            .map(|u| OrganizationMemberResponse { invitation_pending: pending.contains(&u.id), id: u.id, username: u.username.as_str().to_string(), email: u.email, is_organization_admin: u.is_organization_admin })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct InviteOrganizationMemberRequest {
    username: String,
    email: String,
    #[serde(default)]
    is_organization_admin: bool,
}

async fn invite_organization_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<InviteOrganizationMemberRequest>,
) -> Result<(StatusCode, Json<OrganizationMemberResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    // is_super_admin is never read from this request — an org-scoped invite can never grant it.
    let member_id = state
        .invite_user
        .execute(id, body.is_organization_admin, &body.username, &body.email, false)
        .await
        .map_err(|e| application_error_response("failed to invite organization member", e))?;
    Ok((
        StatusCode::CREATED,
        Json(OrganizationMemberResponse { id: member_id, username: body.username, email: Some(body.email), is_organization_admin: body.is_organization_admin, invitation_pending: true }),
    ))
}

#[derive(Deserialize)]
struct SetOrganizationMemberAdminRequest {
    is_organization_admin: bool,
}

async fn set_organization_member_admin(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetOrganizationMemberAdminRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let not_found = || (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() }));
    let target = state
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| application_error_response("failed to look up organization member", e.into()))?
        .ok_or_else(not_found)?;
    if target.organization_id != id {
        // Same privacy stance as require_same_organization: don't confirm this user exists in a different organization.
        return Err(not_found());
    }
    state
        .set_organization_admin
        .execute(user_id, body.is_organization_admin)
        .await
        .map_err(|e| application_error_response("failed to update organization admin status", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_identity_provider(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let config = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to get identity provider", e.into()))?;
    let body = match config {
        None => serde_json::json!({ "type": null }),
        Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) => serde_json::json!({
            "type": "ldap",
            "server_url": ldap.server_url,
            "bind_dn": ldap.bind_dn,
            "bind_password_set": true,
            "user_search_base": ldap.user_search_base,
            "user_search_filter": ldap.user_search_filter,
            "email_attribute": ldap.email_attribute,
        }),
        Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc)) => serde_json::json!({
            "type": "oidc",
            "issuer_url": oidc.issuer_url,
            "client_id": oidc.client_id,
            "client_secret_set": true,
        }),
    };
    Ok(Json(body))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SetIdentityProviderRequest {
    Ldap {
        server_url: String,
        bind_dn: String,
        /// Omitted (or absent) means "keep the existing password" — only meaningful when a configuration of the same type already exists; required on first-time setup.
        #[serde(default)]
        bind_password: Option<String>,
        user_search_base: String,
        user_search_filter: String,
        email_attribute: String,
    },
    Oidc {
        issuer_url: String,
        client_id: String,
        /// Omitted (or absent) means "keep the existing secret" — only meaningful when a configuration of the same type already exists; required on first-time setup.
        #[serde(default)]
        client_secret: Option<String>,
    },
}

async fn set_identity_provider(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetIdentityProviderRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;

    let config = match body {
        SetIdentityProviderRequest::Ldap { server_url, bind_dn, bind_password, user_search_base, user_search_filter, email_attribute } => {
            let bind_password = match bind_password {
                Some(password) if !password.trim().is_empty() => password,
                _ => {
                    let existing = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to load existing identity provider", e.into()))?;
                    match existing {
                        Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) => ldap.bind_password,
                        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "bind_password is required when configuring LDAP for the first time".to_string() }))),
                    }
                }
            };
            if server_url.trim().is_empty() || bind_dn.trim().is_empty() || user_search_base.trim().is_empty() || user_search_filter.trim().is_empty() || email_attribute.trim().is_empty() {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "all LDAP fields except bind_password (when updating) are required".to_string() })));
            }
            hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig { server_url, bind_dn, bind_password, user_search_base, user_search_filter, email_attribute })
        }
        SetIdentityProviderRequest::Oidc { issuer_url, client_id, client_secret } => {
            let client_secret = match client_secret {
                Some(secret) if !secret.trim().is_empty() => secret,
                _ => {
                    let existing = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to load existing identity provider", e.into()))?;
                    match existing {
                        Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc)) => oidc.client_secret,
                        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "client_secret is required when configuring OIDC for the first time".to_string() }))),
                    }
                }
            };
            if issuer_url.trim().is_empty() || client_id.trim().is_empty() {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "issuer_url and client_id are required".to_string() })));
            }
            hangar_domain::sso::IdentityProviderConfig::Oidc(hangar_domain::sso::OidcConfig { issuer_url, client_id, client_secret })
        }
    };
    state.identity_providers.set(id, &config).await.map_err(|e| application_error_response("failed to set identity provider", e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_identity_provider(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.identity_providers.clear(id).await.map_err(|e| application_error_response("failed to clear identity provider", e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Local copy of the established per-file pattern (see repositories.rs's own `test_config()`/`bearer()`).
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

    // These tests aren't about organization scoping, so the public organization is a fine default for both accounts.
    async fn bearer(state: &AppState, organization_id: uuid::Uuid, username: &str, password: &str, is_super_admin: bool) -> String {
        state.create_user.execute(organization_id, username, password, is_super_admin).await.unwrap();
        state.authenticate_user.execute(username, password).await.unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_create_an_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"slug":"acme","display_name":"Acme Corp"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_super_admin_cannot_create_an_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"slug":"acme","display_name":"Acme Corp"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_list_organizations(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/organizations").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let public = json.as_array().unwrap().iter().find(|o| o["slug"] == "public").unwrap();
        assert_eq!(public["is_public"], true, "the seeded public organization must report is_public so clients can pick a sane default filter");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_an_organization_never_reports_it_as_public(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"slug":"acme","display_name":"Acme"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["is_public"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_super_admin_cannot_list_organizations(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/organizations").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_get_any_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/organizations/{acme_id}")).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["slug"], "acme");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_get_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_get_their_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_of_a_different_organization_gets_not_found_for_get_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri(format!("/api/organizations/{acme_id}")).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn getting_an_unconfigured_organizations_identity_provider_returns_no_type(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["type"].is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_configure_ldap_for_any_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"type":"ldap","server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "ldap");
        assert_eq!(json["server_url"], "ldap://dc.corp.example:389");
        assert_eq!(json["bind_password_set"], true);
        assert!(json.get("bind_password").is_none(), "the secret must never be echoed back");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_configure_oidc_for_any_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar","client_secret":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "oidc");
        assert_eq!(json["issuer_url"], "https://accounts.example.com");
        assert_eq!(json["client_secret_set"], true);
        assert!(json.get("client_secret").is_none(), "the secret must never be echoed back");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn configuring_oidc_replaces_an_existing_ldap_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        state
            .identity_providers
            .set(
                public_org.id,
                &hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig {
                    server_url: "ldap://dc.corp.example:389".to_string(),
                    bind_dn: "cn=service,dc=corp,dc=example".to_string(),
                    bind_password: "s3cret!".to_string(),
                    user_search_base: "ou=people,dc=corp,dc=example".to_string(),
                    user_search_filter: "(uid={username})".to_string(),
                    email_attribute: "mail".to_string(),
                }),
            )
            .await
            .unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar","client_secret":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let stored = state.identity_providers.get(public_org.id).await.unwrap();
        assert!(matches!(stored, Some(hangar_domain::sso::IdentityProviderConfig::Oidc(_))), "the old LDAP config must be fully replaced, not merged");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn configuring_oidc_without_a_client_secret_on_first_setup_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_configure_ldap(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"type":"ldap","server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clearing_removes_the_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        state
            .identity_providers
            .set(
                public_org.id,
                &hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig {
                    server_url: "ldap://dc.corp.example:389".to_string(),
                    bind_dn: "cn=service,dc=corp,dc=example".to_string(),
                    bind_password: "s3cret!".to_string(),
                    user_search_base: "ou=people,dc=corp,dc=example".to_string(),
                    user_search_filter: "(uid={username})".to_string(),
                    email_attribute: "mail".to_string(),
                }),
            )
            .await
            .unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        assert_eq!(state.identity_providers.get(public_org.id).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_list_any_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{acme_id}/users"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let members = json.as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0]["username"], "acme-member");
        assert_eq!(members[0]["is_organization_admin"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_list_their_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_list_their_own_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_of_a_different_organization_gets_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{acme_id}/users"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_invite_a_member_into_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"username":"newmember","email":"newmember@example.com","is_organization_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let created = state.users.find_by_username(&hangar_domain::user::Username::parse("newmember").unwrap()).await.unwrap().unwrap();
        assert_eq!(created.organization_id, public_org.id);
        assert!(!created.is_super_admin, "an org-scoped invite must never grant super-admin");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn inviting_a_member_ignores_a_forged_is_super_admin_field(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        // is_super_admin isn't part of the request DTO — sending it anyway must be silently ignored, not deserialization-error, and must never apply.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"username":"sneaky","email":"sneaky@example.com","is_organization_admin":false,"is_super_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let created = state.users.find_by_username(&hangar_domain::user::Username::parse("sneaky").unwrap()).await.unwrap().unwrap();
        assert!(!created.is_super_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_promote_a_member_of_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(public_org.id, "member", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{member_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.users.find_by_id(member_id).await.unwrap().unwrap().is_organization_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn promoting_a_member_of_a_different_organization_is_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let outsider_id = state.create_user.execute(acme_id, "outsider", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{outsider_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!state.users.find_by_id(outsider_id).await.unwrap().unwrap().is_organization_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_promote_anyone(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let member_id = state.create_user.execute(public_org.id, "member", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{member_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
