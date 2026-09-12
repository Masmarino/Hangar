use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hangar_application::use_cases::list_repository_packages::{RepositoryPackageTree, VulnerabilitySummary};
use hangar_domain::docker_registry::DockerImageName;
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};
use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
use hangar_domain::permission::Role;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::authz::{effective_repository_role, require_repository_role, require_same_organization};
use crate::dto::{application_error_response, ErrorResponse};
use crate::organization_middleware::ResolvedOrganization;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/repositories", get(list_repositories).post(create_repository))
        .route("/api/repositories/{id}", get(get_repository).patch(rename_repository).delete(delete_repository))
        .route("/api/repositories/{id}/group-members", post(add_group_member))
        .route("/api/repositories/{id}/group-members/{member_id}", axum::routing::delete(remove_group_member))
        .route("/api/repositories/{id}/quota", put(set_repository_quota))
        .route("/api/repositories/{id}/retention", put(set_retention_policy))
        .route("/api/repositories/{id}/permissions", get(list_permissions))
        .route("/api/repositories/{id}/permissions/{user_id}", put(grant_permission).delete(revoke_permission))
        .route("/api/repositories/{id}/packages", get(list_repository_packages))
        .route(
            "/api/repositories/{id}/packages/npm/{name}",
            get(get_npm_package_details).delete(delete_npm_package),
        )
        .route("/api/repositories/{id}/packages/npm/{name}/versions/{version}", axum::routing::delete(delete_npm_package_version))
        .route("/api/repositories/{id}/packages/npm/{name}/audit", get(audit_npm_package))
        .route(
            "/api/repositories/{id}/packages/npm/{name}/versions/{version}/dependency-audit",
            get(get_dependency_audit).post(scan_dependency_tree),
        )
        .route(
            "/api/repositories/{id}/packages/docker/{image}",
            get(get_docker_image_details).delete(delete_docker_image),
        )
        .route("/api/repositories/{id}/packages/docker/{image}/tags/{tag}", axum::routing::delete(delete_docker_tag))
        .route(
            "/api/repositories/{id}/packages/docker/{image}/tags/{tag}/scan",
            get(get_docker_image_scan).post(scan_docker_image),
        )
}

#[derive(Serialize)]
struct RepositoryResponse {
    id: Uuid,
    name: String,
    format: RepositoryFormat,
    repo_type: RepositoryType,
    remote_url: Option<String>,
    /// Never the credentials themselves.
    remote_credentials_set: bool,
    group_members: Vec<Uuid>,
    /// `None` means unlimited.
    quota_bytes: Option<i64>,
    /// `None` disables automatic cleanup.
    retention_keep_last_n: Option<i32>,
    /// `Admin` for a super-admin regardless of any explicit grant. Lets the frontend decide which actions to offer.
    my_role: Role,
}

impl RepositoryResponse {
    fn new(s: PackageRepositorySummary, my_role: Role) -> Self {
        Self {
            id: s.id,
            name: s.name,
            format: s.format,
            repo_type: s.repo_type,
            remote_url: s.remote_url,
            remote_credentials_set: s.remote_username.is_some() || s.remote_password.is_some(),
            group_members: s.group_members,
            quota_bytes: s.quota_bytes,
            retention_keep_last_n: s.retention_keep_last_n,
            my_role,
        }
    }
}

async fn list_repositories(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
) -> Result<Json<Vec<RepositoryResponse>>, StatusCode> {
    let all = state.repositories.list_all().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if user.is_super_admin {
        return Ok(Json(all.into_iter().map(|r| RepositoryResponse::new(r, Role::Admin)).collect()));
    }
    // An organization admin sees every repository in their own org with Admin, regardless
    // of which domain the request came in on — so this scopes by organization_id, not resolved_org.
    if user.is_organization_admin {
        let mine = all.into_iter().filter(|r| r.organization_id == user.organization_id).map(|r| RepositoryResponse::new(r, Role::Admin)).collect();
        return Ok(Json(mine));
    }
    // A regular member only sees repositories in the resolved organization, even if they
    // have stray permission grants elsewhere.
    let all = all.into_iter().filter(|r| r.organization_id == resolved_org.0.id);
    // One batched lookup instead of one `find_role` per repository.
    let roles: std::collections::HashMap<Uuid, Role> =
        state.permissions.list_for_user(user.id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.into_iter().collect();
    let visible = all.filter_map(|repo| roles.get(&repo.id).map(|role| RepositoryResponse::new(repo, *role))).collect();
    Ok(Json(visible))
}

/// A super-admin can target any org via `organization_id`; anyone else always gets their own.
#[derive(Deserialize)]
struct OrgScopeParams {
    organization_id: Option<Uuid>,
}

fn target_organization_id(user: &AuthUser, resolved_org: &ResolvedOrganization, requested: Option<Uuid>) -> Uuid {
    if user.is_super_admin { requested.unwrap_or(resolved_org.0.id) } else { user.organization_id }
}

#[derive(Deserialize)]
struct CreateRepositoryRequest {
    name: String,
    format: RepositoryFormat,
    repo_type: RepositoryType,
    remote_url: Option<String>,
    /// Ignored for any repo_type other than `proxy`.
    #[serde(default)]
    remote_username: Option<String>,
    #[serde(default)]
    remote_password: Option<String>,
    /// For a `group` repository: member repositories in resolution order.
    #[serde(default)]
    group_members: Option<Vec<Uuid>>,
    /// `None` (the default) leaves the quota unlimited.
    #[serde(default)]
    quota_bytes: Option<i64>,
    /// `None` (the default) leaves automatic cleanup disabled.
    #[serde(default)]
    retention_keep_last_n: Option<i32>,
}

async fn create_repository(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Query(scope): Query<OrgScopeParams>,
    Json(body): Json<CreateRepositoryRequest>,
) -> Result<(StatusCode, Json<RepositoryResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Non-super-admins must be an admin of the org their own subdomain resolves to.
    if !user.is_super_admin {
        require_same_organization(&user, resolved_org.0.id)
            .map_err(|status| (status, Json(ErrorResponse { error: "not found".to_string() })))?;
        if !user.is_organization_admin {
            return Err((StatusCode::FORBIDDEN, Json(ErrorResponse { error: "forbidden".to_string() })));
        }
    }
    let organization_id = target_organization_id(&user, &resolved_org, scope.organization_id);
    let group_members = body.group_members.unwrap_or_default();

    // Validate every member up front, before creating anything.
    if !group_members.is_empty() {
        if body.repo_type != RepositoryType::Group {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "group_members is only valid for a group repository".to_string() }),
            ));
        }
        for member_id in &group_members {
            let member = state
                .repositories
                .find_by_id(*member_id)
                .await
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
                .ok_or_else(|| {
                    application_error_response(
                        "failed to create repository",
                        hangar_domain::error::DomainError::UnknownGroupMember(*member_id).into(),
                    )
                })?;
            // Checked up front so a cross-org member is rejected before the repository is created, not after.
            if member.organization_id != organization_id {
                return Err(application_error_response(
                    "failed to create repository",
                    hangar_domain::error::DomainError::GroupMemberOrganizationMismatch(*member_id).into(),
                ));
            }
            if member.format != body.format {
                return Err(application_error_response(
                    "failed to create repository",
                    hangar_domain::error::DomainError::GroupMemberFormatMismatch(*member_id).into(),
                ));
            }
        }
    }

    let id = state
        .create_repository
        .execute(
            organization_id,
            &body.name,
            body.format,
            body.repo_type,
            body.remote_url.clone(),
            body.remote_username.clone(),
            body.remote_password.clone(),
            user.id,
        )
        .await
        .map_err(|e| application_error_response("failed to create repository", e))?;

    for (position, member_id) in group_members.iter().enumerate() {
        state
            .add_group_member
            .execute(id, *member_id, position as i32, user.id)
            .await
            .map_err(|e| application_error_response("failed to add group member", e))?;
    }
    if let Some(quota_bytes) = body.quota_bytes {
        state
            .set_repository_quota
            .execute(id, Some(quota_bytes), user.id)
            .await
            .map_err(|e| application_error_response("failed to set repository quota", e))?;
    }
    if let Some(keep_last_n) = body.retention_keep_last_n {
        state
            .set_retention_policy
            .execute(id, Some(keep_last_n), user.id)
            .await
            .map_err(|e| application_error_response("failed to set retention policy", e))?;
    }

    let created = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    Ok((StatusCode::CREATED, Json(RepositoryResponse::new(created, Role::Admin))))
}

async fn get_repository(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<RepositoryResponse>, StatusCode> {
    let repo = state.repositories.find_by_id(id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::NOT_FOUND)?;
    // 404 not 403 — a cross-org caller shouldn't learn the repo exists at all.
    require_same_organization(&user, repo.organization_id)?;
    require_repository_role(&state, &user, id, Role::Read, "view repository").await?;
    let my_role = effective_repository_role(&state, &user, id).await?.ok_or(StatusCode::FORBIDDEN)?;
    Ok(Json(RepositoryResponse::new(repo, my_role)))
}

#[derive(Deserialize)]
struct RenameRepositoryRequest {
    name: String,
}

async fn rename_repository(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<RenameRepositoryRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "rename repository")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.rename_repository.execute(id, &body.name, user.id).await.map_err(|e| application_error_response("failed to rename repository", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_repository(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "delete repository")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.delete_repository.execute(id, user.id).await.map_err(|e| application_error_response("failed to delete repository", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AddGroupMemberRequest {
    member_repository_id: Uuid,
    position: i32,
}

async fn add_group_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<AddGroupMemberRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "add group member")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.add_group_member.execute(id, body.member_repository_id, body.position, user.id).await.map_err(|e| application_error_response("failed to add group member", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_group_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "remove group member")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.remove_group_member.execute(id, member_id, user.id).await.map_err(|e| application_error_response("failed to remove group member", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SetRepositoryQuotaRequest {
    /// `None` (a JSON `null`) clears the quota back to unlimited.
    quota_bytes: Option<i64>,
}

async fn set_repository_quota(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetRepositoryQuotaRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "set repository quota")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.set_repository_quota.execute(id, body.quota_bytes, user.id).await.map_err(|e| application_error_response("failed to set repository quota", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SetRetentionPolicyRequest {
    /// `None` (a JSON `null`) disables automatic cleanup.
    keep_last_n_versions: Option<i32>,
}

async fn set_retention_policy(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetRetentionPolicyRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let summary = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, summary.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "set retention policy")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state
        .set_retention_policy
        .execute(id, body.keep_last_n_versions, user.id)
        .await
        .map_err(|e| application_error_response("failed to set retention policy", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct PermissionEntryResponse {
    user_id: Uuid,
    username: String,
    role: Role,
}

async fn list_permissions(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<Vec<PermissionEntryResponse>>, StatusCode> {
    let repo = state.repositories.find_by_id(id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::NOT_FOUND)?;
    require_same_organization(&user, repo.organization_id)?;
    require_repository_role(&state, &user, id, Role::Read, "view permissions").await?;
    let entries = state.permissions.list_for_repository(id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let users = state.users.list_all().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let username_by_id: std::collections::HashMap<Uuid, String> = users.into_iter().map(|u| (u.id, u.username.as_str().to_string())).collect();
    let result = entries
        .into_iter()
        .map(|(user_id, role)| {
            let username = username_by_id.get(&user_id).cloned().unwrap_or_else(|| "unknown".to_string());
            PermissionEntryResponse { user_id, username, role }
        })
        .collect();
    Ok(Json(result))
}

#[derive(Deserialize)]
struct GrantPermissionRequest {
    role: Role,
}

async fn grant_permission(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, target_user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<GrantPermissionRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "grant permission")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.grant_permission.execute(target_user_id, id, body.role, user.id).await.map_err(|e| application_error_response("failed to grant permission", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_permission(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, target_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Admin, "revoke permission")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.revoke_permission.execute(target_user_id, id, user.id).await.map_err(|e| application_error_response("failed to revoke permission", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(tag = "format", rename_all = "snake_case")]
enum RepositoryPackagesResponse {
    Npm { packages: Vec<NpmPackageTreeResponse> },
    Docker { images: Vec<DockerImageTreeResponse> },
}

#[derive(Serialize)]
struct NpmPackageTreeResponse {
    name: String,
    versions: Vec<NpmPackageVersionResponse>,
    vulnerability_summary: VulnerabilitySummaryResponse,
}

#[derive(Serialize)]
struct NpmPackageVersionResponse {
    version: String,
    published_at: DateTime<Utc>,
    size_bytes: i64,
    deprecated: bool,
}

#[derive(Serialize)]
struct DockerImageTreeResponse {
    image_name: String,
    tags: Vec<String>,
    vulnerability_summary: VulnerabilitySummaryResponse,
}

#[derive(Serialize)]
struct VulnerabilitySummaryResponse {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
}

impl From<VulnerabilitySummary> for VulnerabilitySummaryResponse {
    fn from(s: VulnerabilitySummary) -> Self {
        Self { critical: s.critical, high: s.high, medium: s.medium, low: s.low }
    }
}

async fn list_repository_packages(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<RepositoryPackagesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "browse repository packages")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let tree = state
        .list_repository_packages
        .execute(id, repo.format)
        .await
        .map_err(|e| application_error_response("failed to list repository packages", e))?;
    Ok(Json(match tree {
        RepositoryPackageTree::Npm(packages) => RepositoryPackagesResponse::Npm {
            packages: packages
                .into_iter()
                .map(|p| NpmPackageTreeResponse {
                    name: p.name,
                    versions: p
                        .versions
                        .into_iter()
                        .map(|v| NpmPackageVersionResponse {
                            version: v.version,
                            published_at: v.published_at,
                            size_bytes: v.size_bytes,
                            deprecated: v.deprecated,
                        })
                        .collect(),
                    vulnerability_summary: p.vulnerability_summary.into(),
                })
                .collect(),
        },
        RepositoryPackageTree::Docker(images) => RepositoryPackagesResponse::Docker {
            images: images
                .into_iter()
                .map(|i| DockerImageTreeResponse { image_name: i.image_name, tags: i.tags, vulnerability_summary: i.vulnerability_summary.into() })
                .collect(),
        },
    }))
}

#[derive(Serialize)]
struct NpmVersionDetailResponse {
    version: String,
    published_at: DateTime<Utc>,
    size_bytes: i64,
    deprecated: bool,
    deprecated_message: Option<String>,
    shasum: String,
}

#[derive(Serialize)]
struct NpmDistTagDetailResponse {
    tag: String,
    version: String,
}

#[derive(Serialize)]
struct NpmPackageDetailsResponse {
    name: String,
    versions: Vec<NpmVersionDetailResponse>,
    dist_tags: Vec<NpmDistTagDetailResponse>,
}

async fn get_npm_package_details(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name)): Path<(Uuid, String)>,
) -> Result<Json<NpmPackageDetailsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "view package details")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    let details = state
        .get_npm_package_details
        .execute(id, &parsed)
        .await
        .map_err(|e| application_error_response("failed to get npm package details", e))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "package not found".to_string() })))?;
    Ok(Json(NpmPackageDetailsResponse {
        name: details.name,
        versions: details
            .versions
            .into_iter()
            .map(|v| NpmVersionDetailResponse {
                version: v.version,
                published_at: v.published_at,
                size_bytes: v.size_bytes,
                deprecated: v.deprecated,
                deprecated_message: v.deprecated_message,
                shasum: v.shasum,
            })
            .collect(),
        dist_tags: details.dist_tags.into_iter().map(|t| NpmDistTagDetailResponse { tag: t.tag, version: t.version }).collect(),
    }))
}

async fn delete_npm_package(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name)): Path<(Uuid, String)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "delete npm package")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    state
        .unpublish_npm_package
        .execute_whole_package(id, &parsed, user.id)
        .await
        .map_err(|e| application_error_response("failed to delete npm package", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_npm_package_version(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name, version)): Path<(Uuid, String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "delete npm package version")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed_name =
        NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    let parsed_version =
        NpmVersion::parse(&version).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid version".to_string() })))?;
    state
        .unpublish_npm_package
        .execute_version(id, &parsed_name, &parsed_version, user.id)
        .await
        .map_err(|e| application_error_response("failed to delete npm package version", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct NpmAdvisoryResponse {
    id: i64,
    url: String,
    title: String,
    severity: String,
    vulnerable_versions: String,
    cwe: Vec<String>,
    cvss_score: Option<f64>,
}

async fn audit_npm_package(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name)): Path<(Uuid, String)>,
) -> Result<Json<Vec<NpmAdvisoryResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "audit npm package")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    let advisories = state
        .audit_npm_package
        .execute(id, &parsed)
        .await
        .map_err(|e| application_error_response("failed to audit npm package", e))?;
    Ok(Json(
        advisories
            .into_iter()
            .map(|a| NpmAdvisoryResponse {
                id: a.id,
                url: a.url,
                title: a.title,
                severity: a.severity,
                vulnerable_versions: a.vulnerable_versions,
                cwe: a.cwe,
                cvss_score: a.cvss_score,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct DependencyAuditFindingResponse {
    dependency_name: String,
    dependency_version: String,
    advisory: NpmAdvisoryResponse,
}

#[derive(Serialize)]
struct DependencyAuditResultResponse {
    scanned_at: DateTime<Utc>,
    packages_scanned: i32,
    truncated: bool,
    findings: Vec<DependencyAuditFindingResponse>,
}

impl From<hangar_domain::npm_audit::DependencyAuditResult> for DependencyAuditResultResponse {
    fn from(result: hangar_domain::npm_audit::DependencyAuditResult) -> Self {
        Self {
            scanned_at: result.scanned_at,
            packages_scanned: result.packages_scanned,
            truncated: result.truncated,
            findings: result
                .findings
                .into_iter()
                .map(|f| DependencyAuditFindingResponse {
                    dependency_name: f.dependency_name,
                    dependency_version: f.dependency_version,
                    advisory: NpmAdvisoryResponse {
                        id: f.advisory.id,
                        url: f.advisory.url,
                        title: f.advisory.title,
                        severity: f.advisory.severity,
                        vulnerable_versions: f.advisory.vulnerable_versions,
                        cwe: f.advisory.cwe,
                        cvss_score: f.advisory.cvss_score,
                    },
                })
                .collect(),
        }
    }
}

async fn get_dependency_audit(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name, version)): Path<(Uuid, String, String)>,
) -> Result<Json<Option<DependencyAuditResultResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "read npm dependency audit")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed_name =
        NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    let parsed_version =
        NpmVersion::parse(&version).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid version".to_string() })))?;
    let result = state
        .get_dependency_audit
        .execute(id, &parsed_name, &parsed_version)
        .await
        .map_err(|e| application_error_response("failed to read dependency audit", e))?;
    Ok(Json(result.map(DependencyAuditResultResponse::from)))
}

async fn scan_dependency_tree(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, name, version)): Path<(Uuid, String, String)>,
) -> Result<Json<DependencyAuditResultResponse>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "run npm dependency audit")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed_name =
        NpmPackageName::parse(&name).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid package name".to_string() })))?;
    let parsed_version =
        NpmVersion::parse(&version).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid version".to_string() })))?;
    let result = state
        .scan_dependency_tree
        .execute(id, &parsed_name, &parsed_version)
        .await
        .map_err(|e| application_error_response("failed to scan dependency tree", e))?;
    Ok(Json(result.into()))
}

#[derive(Serialize)]
struct DockerTagDetailResponse {
    tag: String,
    digest: String,
    media_type: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct DockerImageDetailsResponse {
    image_name: String,
    tags: Vec<DockerTagDetailResponse>,
}

async fn get_docker_image_details(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, image)): Path<(Uuid, String)>,
) -> Result<Json<DockerImageDetailsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "view image details")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = DockerImageName::parse(&image).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid image name".to_string() })))?;
    let details = state.get_docker_image_details.execute(id, &parsed).await.map_err(|e| application_error_response("failed to get docker image details", e))?;
    Ok(Json(DockerImageDetailsResponse {
        image_name: details.image_name,
        tags: details
            .tags
            .into_iter()
            .map(|t| DockerTagDetailResponse { tag: t.tag, digest: t.digest, media_type: t.media_type, created_at: t.created_at })
            .collect(),
    }))
}

#[derive(Serialize)]
struct DockerVulnerabilityResponse {
    id: String,
    package_name: String,
    installed_version: String,
    fixed_version: Option<String>,
    severity: String,
    title: Option<String>,
    primary_url: Option<String>,
}

#[derive(Serialize)]
struct DockerImageScanResultResponse {
    scanned_at: DateTime<Utc>,
    vulnerabilities: Vec<DockerVulnerabilityResponse>,
}

impl From<hangar_domain::docker_scan::DockerImageScanResult> for DockerImageScanResultResponse {
    fn from(result: hangar_domain::docker_scan::DockerImageScanResult) -> Self {
        Self {
            scanned_at: result.scanned_at,
            vulnerabilities: result
                .vulnerabilities
                .into_iter()
                .map(|v| DockerVulnerabilityResponse {
                    id: v.id,
                    package_name: v.package_name,
                    installed_version: v.installed_version,
                    fixed_version: v.fixed_version,
                    severity: v.severity,
                    title: v.title,
                    primary_url: v.primary_url,
                })
                .collect(),
        }
    }
}

async fn get_docker_image_scan(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, image, tag)): Path<(Uuid, String, String)>,
) -> Result<Json<Option<DockerImageScanResultResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Read, "read docker image scan")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = DockerImageName::parse(&image).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid image name".to_string() })))?;
    let result = state
        .get_docker_image_scan
        .execute(id, &parsed, &tag)
        .await
        .map_err(|e| application_error_response("failed to read docker image scan", e))?;
    Ok(Json(result.map(DockerImageScanResultResponse::from)))
}

async fn scan_docker_image(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, image, tag)): Path<(Uuid, String, String)>,
) -> Result<Json<DockerImageScanResultResponse>, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "run docker image scan")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = DockerImageName::parse(&image).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid image name".to_string() })))?;
    let result = state
        .scan_docker_image
        .execute(id, &parsed, &tag, user.id)
        .await
        .map_err(|e| application_error_response("failed to scan docker image", e))?;
    Ok(Json(result.into()))
}

async fn delete_docker_tag(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, image, tag)): Path<(Uuid, String, String)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "delete docker tag")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = DockerImageName::parse(&image).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid image name".to_string() })))?;
    let manifest = state
        .docker_manifests
        .find_manifest_by_tag(id, &parsed, &tag)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "tag not found".to_string() })))?;
    state
        .delete_docker_manifest
        .execute(id, &parsed, &manifest.digest, user.id)
        .await
        .map_err(|e| application_error_response("failed to delete docker tag", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_docker_image(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, image)): Path<(Uuid, String)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let repo = state
        .repositories
        .find_by_id(id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_same_organization(&user, repo.organization_id)
        .map_err(|status| (status, Json(ErrorResponse { error: "repository not found".to_string() })))?;
    require_repository_role(&state, &user, id, Role::Write, "delete docker image")
        .await
        .map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let parsed = DockerImageName::parse(&image).map_err(|_| (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "invalid image name".to_string() })))?;
    state.delete_docker_image.execute(id, &parsed, user.id).await.map_err(|e| application_error_response("failed to delete docker image", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

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

    async fn bearer(state: &AppState, organization_id: Uuid, username: &str, password: &str, is_super_admin: bool) -> String {
        state.create_user.execute(organization_id, username, password, is_super_admin).await.unwrap();
        state.authenticate_user.execute(username, password).await.unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn super_admin_can_create_a_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"my-npm-repo","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_target_a_specific_organizations_repository_via_the_query_param(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let app = build_router(state.clone());

        // No `host` header — this would otherwise resolve to the public organization.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/repositories?organization_id={acme_id}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"acme-repo","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let created_id = Uuid::parse_str(json["id"].as_str().unwrap()).unwrap();
        let created = state.repositories.find_by_id(created_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, acme_id, "?organization_id= must target that organization, not whichever one the request's domain resolves to");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_use_the_organization_id_query_param_to_create_a_repository_in_another_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/repositories?organization_id={other_id}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    // organization_id doesn't override the domain for a non-super-admin.
                    .header("host", "acme.hangar.localhost")
                    .body(Body::from(r#"{"name":"escape-attempt","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let created_id = Uuid::parse_str(json["id"].as_str().unwrap()).unwrap();
        let created = state.repositories.find_by_id(created_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, acme_id, "an organization admin must not be able to use ?organization_id= to escape their own organization");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn renaming_a_repository_to_an_already_taken_name_returns_the_real_error_message(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "taken-name", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let other_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "other-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/repositories/{other_id}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"taken-name"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!json["error"].as_str().unwrap_or("").is_empty(), "the failure must carry a real message, not an empty body");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_group_repository_can_be_created_with_initial_members_in_order(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let member_a = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member-a", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let member_b = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member-b", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(
                        r#"{{"name":"my-group","format":"npm","repo_type":"group","remote_url":null,"group_members":["{member_a}","{member_b}"]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["group_members"], serde_json::json!([member_a, member_b]));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_a_group_with_an_unknown_member_is_rejected_and_creates_nothing(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let ghost_id = Uuid::new_v4();
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(
                        r#"{{"name":"my-group","format":"npm","repo_type":"group","remote_url":null,"group_members":["{ghost_id}"]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        let retry = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"my-group","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), axum::http::StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_a_group_with_a_cross_organization_member_is_rejected_and_creates_nothing(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let acme_admin =
            state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        // A member repository in a DIFFERENT org than this request resolves to (public, since no Host header is set below).
        let cross_org_member =
            state.create_repository.execute(acme_id, "acme-member", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, acme_admin).await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(
                        r#"{{"name":"my-group","format":"npm","repo_type":"group","remote_url":null,"group_members":["{cross_org_member}"]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        // Proves no orphaned repository was left behind: the same name is still free.
        assert!(state.repositories.find_by_org_and_name(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-group").await.unwrap().is_none());

        let retry = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"my-group","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), axum::http::StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_a_group_with_a_mismatched_format_member_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let docker_member =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "docker-member", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(
                        r#"{{"name":"my-npm-group","format":"npm","repo_type":"group","remote_url":null,"group_members":["{docker_member}"]}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_a_proxy_with_remote_credentials_reports_them_set_but_never_returns_them(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"name":"my-proxy","format":"npm","repo_type":"proxy","remote_url":"https://registry.example.com","remote_username":"svc-account","remote_password":"s3cret-token"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("s3cret-token"), "the raw password must never appear in the response body: {text}");
        assert!(!text.contains("svc-account"), "the raw username must never appear in the response body: {text}");
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["remote_credentials_set"], true);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn quota_and_retention_can_be_set_at_creation_time(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"name":"my-repo","format":"npm","repo_type":"hosted","remote_url":null,"quota_bytes":1000000,"retention_keep_last_n":5}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["quota_bytes"], 1000000);
        assert_eq!(json["retention_keep_last_n"], 5);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_duplicate_repository_name_keeps_its_specific_error_message(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        state
            .create_repository
            .execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "taken-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, Uuid::new_v4())
            .await
            .unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"taken-repo","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "repository name already taken");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_repository_name_is_reusable_after_deletion(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await;
        let admin_id = state.users.find_by_username(&hangar_domain::user::Username::parse("admin").unwrap()).await.unwrap().unwrap().id;
        let first_id = state
            .create_repository
            .execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "recyclable", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        state.delete_repository.execute(first_id, admin_id).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"recyclable","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_create_a_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/repositories")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"my-npm-repo","format":"npm","repo_type":"hosted","remote_url":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_admin_sets_and_clears_a_repository_quota(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/quota"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"quota_bytes":1000000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["quota_bytes"], 1000000);

        let clear_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/quota"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"quota_bytes":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear_response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_negative_quota_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/quota"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"quota_bytes":-1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_write_only_user_cannot_set_the_repository_quota(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let writer_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "writer", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(writer_id, repo_id, Role::Write, admin_id).await.unwrap();
        let writer_token = state.authenticate_user.execute("writer", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/quota"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {writer_token}"))
                    .body(Body::from(r#"{"quota_bytes":1000000}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_admin_sets_and_clears_a_retention_policy(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/retention"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"keep_last_n_versions":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["retention_keep_last_n"], 5);

        let clear_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/retention"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"keep_last_n_versions":null}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear_response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_retention_policy_below_one_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/retention"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"keep_last_n_versions":0}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_write_only_user_cannot_set_the_retention_policy(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "my-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let writer_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "writer", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(writer_id, repo_id, Role::Write, admin_id).await.unwrap();
        let writer_token = state.authenticate_user.execute("writer", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/repositories/{repo_id}/retention"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {writer_token}"))
                    .body(Body::from(r#"{"keep_last_n_versions":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_user_without_permission_cannot_view_a_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "private-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "outsider", "sup3r-s3cret!", false).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn granting_read_access_allows_viewing_the_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "shared-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Read, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn adding_a_group_member_via_the_api(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let group_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "group-repo", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, admin_id).await.unwrap();
        let member_repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/repositories/{group_id}/group-members"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(r#"{{"member_repository_id":"{member_repo_id}","position":0}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn listing_permissions_includes_a_granted_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "shared-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Write, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/permissions"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["username"], "member");
        assert_eq!(entries[0]["role"], "write");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn browsing_an_npm_repository_lists_its_packages_and_versions(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        state
            .npm_packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: NpmVersion::parse("1.0.0").unwrap(),
                manifest: serde_json::json!({}),
                shasum: "shasum".to_string(),
                integrity: "integrity".to_string(),
                tarball_storage_key: "key".to_string(),
                tarball_size_bytes: 42,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: chrono::Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["format"], "npm");
        assert_eq!(json["packages"][0]["name"], "left-pad");
        assert_eq!(json["packages"][0]["versions"][0]["version"], "1.0.0");
        assert_eq!(json["packages"][0]["versions"][0]["size_bytes"], 42);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn browsing_a_docker_repository_lists_its_images_and_tags(pool: sqlx::PgPool) {
        use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerMediaType};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "docker-repo", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        let image_name = DockerImageName::parse("my-app").unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            image_name: image_name.clone(),
            digest: Digest::of(b"{}"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: chrono::Utc::now(),
        };
        state.docker_manifests.insert_manifest(&manifest, &[]).await.unwrap();
        state.docker_manifests.set_tag(repo_id, &image_name, "latest", manifest.id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["format"], "docker");
        assert_eq!(json["images"][0]["image_name"], "my-app");
        assert_eq!(json["images"][0]["tags"], serde_json::json!(["latest"]));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_user_without_permission_cannot_browse_a_repositorys_packages(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "private-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = bearer(&state, Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "outsider", "sup3r-s3cret!", false).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn viewing_npm_package_details_lists_its_versions_and_dist_tags(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state
            .npm_packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: version.clone(),
                manifest: serde_json::json!({}),
                shasum: "shasum".to_string(),
                integrity: "integrity".to_string(),
                tarball_storage_key: "key".to_string(),
                tarball_size_bytes: 42,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: chrono::Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        state.npm_packages.set_dist_tag(package.id, "latest", &version).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "left-pad");
        assert_eq!(json["versions"][0]["version"], "1.0.0");
        assert_eq!(json["versions"][0]["size_bytes"], 42);
        assert_eq!(json["dist_tags"][0]["tag"], "latest");
        assert_eq!(json["dist_tags"][0]["version"], "1.0.0");
    }

    // Ground truth against the real npm advisory database.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    #[ignore = "requires network access to registry.npmjs.org"]
    async fn auditing_an_npm_package_reports_known_advisories_for_its_stored_version(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("minimist").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        state
            .npm_packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: NpmVersion::parse("0.0.8").unwrap(),
                manifest: serde_json::json!({}),
                shasum: "shasum".to_string(),
                integrity: "integrity".to_string(),
                tarball_storage_key: "key".to_string(),
                tarball_size_bytes: 1,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: chrono::Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/minimist/audit"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let advisories = json.as_array().unwrap();
        assert!(!advisories.is_empty());
        assert!(advisories.iter().any(|a| a["title"].as_str().unwrap().to_lowercase().contains("prototype pollution")));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_an_npm_package_version_removes_only_that_version(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        for raw_version in ["1.0.0", "2.0.0"] {
            let tarball_storage_key = format!("left-pad-{raw_version}.tgz");
            state.storage.write(repo_id, &tarball_storage_key, b"tarball bytes").await.unwrap();
            state
                .npm_packages
                .insert_version(&NpmPackageVersion {
                    id: Uuid::new_v4(),
                    npm_package_id: package.id,
                    version: NpmVersion::parse(raw_version).unwrap(),
                    manifest: serde_json::json!({}),
                    shasum: "shasum".to_string(),
                    integrity: "integrity".to_string(),
                    tarball_storage_key,
                    tarball_size_bytes: 1,
                    deprecated: false,
                    deprecated_message: None,
                    published_by: None,
                    published_at: chrono::Utc::now(),
                    origin: NpmPackageOrigin::Local,
                })
                .await
                .unwrap();
        }
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad/versions/1.0.0"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let remaining = state.npm_packages.list_versions(package.id).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].version.as_str(), "2.0.0");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_the_whole_npm_package_removes_it_entirely(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        state.storage.write(repo_id, "left-pad-1.0.0.tgz", b"tarball bytes").await.unwrap();
        state
            .npm_packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: NpmVersion::parse("1.0.0").unwrap(),
                manifest: serde_json::json!({}),
                shasum: "shasum".to_string(),
                integrity: "integrity".to_string(),
                tarball_storage_key: "left-pad-1.0.0.tgz".to_string(),
                tarball_size_bytes: 1,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: chrono::Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let repository_id_for_lookup = repo_id;
        let name_for_lookup = NpmPackageName::parse("left-pad").unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        assert!(state.npm_packages.find_package(repository_id_for_lookup, &name_for_lookup).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_read_only_user_cannot_delete_an_npm_package(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "npm-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state
            .npm_packages
            .create_package(&NpmPackage {
                id: Uuid::new_v4(),
                package_repository_id: repo_id,
                name: NpmPackageName::parse("left-pad").unwrap(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata_fetched_at: None,
                cached_metadata: None,
            })
            .await
            .unwrap();
        let reader_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "reader", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(reader_id, repo_id, Role::Read, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("reader", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn viewing_docker_image_details_resolves_each_tags_digest(pool: sqlx::PgPool) {
        use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerMediaType};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "docker-repo", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        let image_name = DockerImageName::parse("my-app").unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            image_name: image_name.clone(),
            digest: Digest::of(b"{}"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: chrono::Utc::now(),
        };
        state.docker_manifests.insert_manifest(&manifest, &[]).await.unwrap();
        state.docker_manifests.set_tag(repo_id, &image_name, "latest", manifest.id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}/packages/docker/my-app"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["image_name"], "my-app");
        assert_eq!(json["tags"][0]["tag"], "latest");
        assert_eq!(json["tags"][0]["digest"], manifest.digest.as_str());
        assert_eq!(json["tags"][0]["media_type"], "application/vnd.docker.distribution.manifest.v2+json");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_a_docker_tag_removes_its_manifest(pool: sqlx::PgPool) {
        use hangar_domain::docker_registry::{Digest, DockerImageName, DockerManifest, DockerMediaType};

        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "docker-repo", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        let image_name = DockerImageName::parse("my-app").unwrap();
        let manifest = DockerManifest {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            image_name: image_name.clone(),
            digest: Digest::of(b"{}"),
            media_type: DockerMediaType::DockerV2Manifest,
            body: b"{}".to_vec(),
            created_at: chrono::Utc::now(),
        };
        state.docker_manifests.insert_manifest(&manifest, &[]).await.unwrap();
        state.docker_manifests.set_tag(repo_id, &image_name, "latest", manifest.id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let repository_id_for_lookup = repo_id;
        let image_name_for_lookup = image_name.clone();
        let digest_for_lookup = manifest.digest.clone();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/repositories/{repo_id}/packages/docker/my-app/tags/latest"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        assert!(state
            .docker_manifests
            .find_manifest_by_digest(repository_id_for_lookup, &image_name_for_lookup, &digest_for_lookup)
            .await
            .unwrap()
            .is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_repository_in_one_organization_is_not_reachable_from_another_organizations_subdomain(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(acme_id, "backend", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        let other_token = bearer(&state, other_id, "other-user", "sup3r-s3cret!", false).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("host", "other.hangar.localhost")
                    .header("authorization", format!("Bearer {other_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_still_reach_any_organizations_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(acme_id, "backend", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();
        let super_admin_token = bearer(&state, other_id, "the-super-admin", "sup3r-s3cret!", true).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("host", "other.hangar.localhost")
                    .header("authorization", format!("Bearer {super_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn adding_a_group_member_to_a_repository_in_another_organization_returns_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(acme_id, "backend-group", RepositoryFormat::Npm, RepositoryType::Group, None, None, None, admin_id)
            .await
            .unwrap();
        let other_token = bearer(&state, other_id, "other-user", "sup3r-s3cret!", false).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/repositories/{repo_id}/group-members"))
                    .header("host", "other.hangar.localhost")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {other_token}"))
                    .body(Body::from(format!(r#"{{"member_repository_id":"{}","position":0}}"#, Uuid::new_v4())))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

    /// Representative of all twelve content routes, which share the same org check.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn npm_package_details_in_one_organization_is_not_reachable_by_a_member_of_another(pool: sqlx::PgPool) {
        use hangar_domain::npm_package::{NpmPackage, NpmPackageName, NpmPackageOrigin, NpmPackageVersion, NpmVersion};

        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state
            .create_repository
            .execute(acme_id, "backend", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
            .await
            .unwrap();

        // A real package must exist first, so the assertion below is explained by the org check, not "not found".
        let package = NpmPackage {
            id: Uuid::new_v4(),
            package_repository_id: repo_id,
            name: NpmPackageName::parse("left-pad").unwrap(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata_fetched_at: None,
            cached_metadata: None,
        };
        state.npm_packages.create_package(&package).await.unwrap();
        let version = NpmVersion::parse("1.0.0").unwrap();
        state
            .npm_packages
            .insert_version(&NpmPackageVersion {
                id: Uuid::new_v4(),
                npm_package_id: package.id,
                version: version.clone(),
                manifest: serde_json::json!({}),
                shasum: "shasum".to_string(),
                integrity: "integrity".to_string(),
                tarball_storage_key: "key".to_string(),
                tarball_size_bytes: 42,
                deprecated: false,
                deprecated_message: None,
                published_by: None,
                published_at: chrono::Utc::now(),
                origin: NpmPackageOrigin::Local,
            })
            .await
            .unwrap();
        state.npm_packages.set_dist_tag(package.id, "latest", &version).await.unwrap();
        // Creating a repository doesn't itself grant the creator a role on it.
        state.grant_permission.execute(admin_id, repo_id, Role::Read, admin_id).await.unwrap();

        // Grant as super-admin (only way to cross orgs), then demote — leaves a stale
        // out-of-org grant. A second super-admin so the demotion below isn't rejected.
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "another-super-admin", "sup3r-s3cret!", true).await.unwrap();
        let other_user_id = state.create_user.execute(other_id, "other-user", "sup3r-s3cret!", true).await.unwrap();
        state.grant_permission.execute(other_user_id, repo_id, Role::Read, admin_id).await.unwrap();
        state.set_super_admin.execute(other_user_id, false).await.unwrap();
        let other_token = state.authenticate_user.execute("other-user", "sup3r-s3cret!").await.unwrap();
        let admin_token = state.authenticate_user.execute("acme-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        // Sanity check: acme's own admin can see the package it just created.
        let acme_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad"))
                    .header("host", "acme.hangar.localhost")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(acme_response.status(), axum::http::StatusCode::OK, "sanity check: the created package must be fetchable by its own organization");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/repositories/{repo_id}/packages/npm/left-pad"))
                    .header("host", "other.hangar.localhost")
                    .header("authorization", format!("Bearer {other_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "a valid role grant on a package that genuinely exists must not be enough to cross an organization boundary"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_a_repository_in_their_org_they_never_created_or_were_granted_on(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let creator_id = state.create_user.execute(acme_id, "creator", "sup3r-s3cret!", false).await.unwrap();
        state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, creator_id).await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/repositories")
                    .header("host", "acme.hangar.localhost")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let repos = json.as_array().unwrap();
        assert_eq!(repos.len(), 1, "an organization admin must see every repository in their own organization, not just ones they created or were explicitly granted on");
        assert_eq!(repos[0]["name"], "acme-repo");
        assert_eq!(repos[0]["my_role"], "admin");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_does_not_see_another_organizations_repositories(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let other_creator = state.create_user.execute(other_id, "other-creator", "sup3r-s3cret!", false).await.unwrap();
        state.create_repository.execute(other_id, "other-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, other_creator).await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/repositories")
                    .header("host", "acme.hangar.localhost")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0, "an organization admin must never see another organization's repositories");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_rename_a_repository_in_their_org_they_never_created_or_were_granted_on(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let creator_id = state.create_user.execute(acme_id, "creator", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, creator_id).await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"renamed-repo"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_of_a_different_organization_cannot_rename_a_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let creator_id = state.create_user.execute(acme_id, "creator", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, creator_id).await.unwrap();
        let org_admin_id = state.create_user.execute(other_id, "other-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("other-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"name":"renamed-repo"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            axum::http::StatusCode::NOT_FOUND,
            "require_same_organization (checked before require_repository_role) must reject a different organization's admin without confirming the repository exists"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_view_a_repository_they_never_created_or_were_granted_on(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let creator_id = state.create_user.execute(acme_id, "creator", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, creator_id).await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK, "require_repository_role already grants an org-admin Read access here — the response body's own my_role computation must not re-check a raw permission grant and 403 anyway");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["my_role"], "admin");
    }
}
